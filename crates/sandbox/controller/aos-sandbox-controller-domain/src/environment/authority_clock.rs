//! Fixed live boot and monotonic-clock fencing for dormant authorities.
//!
//! Protected records may carry a boot identifier and a monotonic validity
//! interval, but those bytes are not evidence that the same kernel is still
//! running. Effect owners sample this boundary immediately around protected
//! state reads and effect dispatch. The qualified Linux source pairs
//! `/proc/sys/kernel/random/boot_id` with `CLOCK_BOOTTIME`. Clock construction
//! is deliberately crate-private: public callers cannot manufacture samples or
//! substitute a weaker source at an authority boundary.

use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

/// Reports unavailable or malformed live boot-clock evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveAuthorityClockErrorV1 {
    /// The platform does not provide a qualified live clock source.
    Unavailable,
    /// The source returned a sentinel, overflowing, or boot-raced sample.
    InvalidSample,
}

impl std::fmt::Display for LiveAuthorityClockErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "live authority clock is unavailable",
            Self::InvalidSample => "live authority clock sample is invalid",
        })
    }
}

impl std::error::Error for LiveAuthorityClockErrorV1 {}

/// Carries one indivisible current-kernel and `CLOCK_BOOTTIME` observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LiveAuthorityClockSampleV1 {
    boot: ObjectDigest,
    boottime_nanoseconds: u64,
}

impl LiveAuthorityClockSampleV1 {
    /// Constructs a sample supplied by an independently protected adapter.
    ///
    /// # Errors
    ///
    /// Returns [`LiveAuthorityClockErrorV1::InvalidSample`] for sentinel
    /// values. Supplying a value does not attest it; authority owners accept
    /// samples only from their injected clock source.
    fn new(
        boot: ObjectDigest,
        boottime_nanoseconds: u64,
    ) -> Result<Self, LiveAuthorityClockErrorV1> {
        if boot.as_bytes() == &[0; 32]
            || boottime_nanoseconds == 0
            || boottime_nanoseconds == u64::MAX
        {
            return Err(LiveAuthorityClockErrorV1::InvalidSample);
        }
        Ok(Self {
            boot,
            boottime_nanoseconds,
        })
    }

    /// Returns the domain-separated current kernel boot commitment.
    #[must_use]
    pub(crate) const fn boot(self) -> ObjectDigest {
        self.boot
    }

    /// Returns the paired `CLOCK_BOOTTIME` value in nanoseconds.
    #[must_use]
    pub(crate) const fn boottime_nanoseconds(self) -> u64 {
        self.boottime_nanoseconds
    }
}

/// Supplies live boot-scoped monotonic observations to protected owners.
trait LiveAuthorityClockSourceV1: Send {
    /// Samples one indivisible live boot-clock pair.
    ///
    /// # Errors
    ///
    /// Returns [`LiveAuthorityClockErrorV1`] when the source is unavailable or
    /// cannot prove that the boot remained stable across the clock read.
    fn sample(&mut self) -> Result<LiveAuthorityClockSampleV1, LiveAuthorityClockErrorV1>;

    fn native_failure(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Rejects every authority request on platforms without an installed source.
#[derive(Clone, Copy, Debug, Default)]
struct UnavailableLiveAuthorityClockV1;

impl LiveAuthorityClockSourceV1 for UnavailableLiveAuthorityClockV1 {
    fn sample(&mut self) -> Result<LiveAuthorityClockSampleV1, LiveAuthorityClockErrorV1> {
        Err(LiveAuthorityClockErrorV1::Unavailable)
    }
}

/// Computes the canonical commitment stored for one Linux kernel boot UUID.
#[must_use]
pub(super) fn linux_kernel_boot_commitment_v1(boot_id: [u8; 16]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.live-authority-clock.linux-boot-id.v1\0")
            .chain_update(boot_id)
            .finalize()
            .into(),
    )
}

/// Samples the current Linux boot identity and `CLOCK_BOOTTIME` directly.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default)]
struct LinuxLiveAuthorityClockV1;

#[cfg(target_os = "linux")]
impl LiveAuthorityClockSourceV1 for LinuxLiveAuthorityClockV1 {
    fn sample(&mut self) -> Result<LiveAuthorityClockSampleV1, LiveAuthorityClockErrorV1> {
        sample_linux_clock_engine_v1(None)
    }
}

// Both dispositions use exactly the original boot→BOOTTIME→boot recipe and
// pure conversion. A failed selected primitive retains its actual native input;
// completed positive primitives may dispose before the next clock primitive.
#[cfg(target_os = "linux")]
fn sample_linux_clock_engine_v1(
    mut original: Option<&mut LiveClockNativeOriginalV1>,
) -> Result<LiveAuthorityClockSampleV1, LiveAuthorityClockErrorV1> {
    use aos_sandbox_linux::boot::KernelBootId;

    let boot_before = match original.as_deref_mut() {
        Some(original) => original.before.observe_once()
            .map(|boot| boot.into_bytes()).map_err(|_| LiveAuthorityClockErrorV1::Unavailable)?,
        None => KernelBootId::current()
            .map_err(|_| LiveAuthorityClockErrorV1::Unavailable)?.into_bytes(),
    };
    let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    if let Some(original) = original.as_deref_mut() { original.boottime = Some(boottime); }
    let boot_after = match original.as_deref_mut() {
        Some(original) => original.after.observe_once()
            .map(|boot| boot.into_bytes()).map_err(|_| LiveAuthorityClockErrorV1::Unavailable)?,
        None => KernelBootId::current()
            .map_err(|_| LiveAuthorityClockErrorV1::Unavailable)?.into_bytes(),
    };
    if boot_before != boot_after {
        return Err(LiveAuthorityClockErrorV1::InvalidSample);
    }
    let seconds =
        u64::try_from(boottime.tv_sec).map_err(|_| LiveAuthorityClockErrorV1::InvalidSample)?;
    let nanoseconds = u64::try_from(boottime.tv_nsec)
        .map_err(|_| LiveAuthorityClockErrorV1::InvalidSample)?;
    let value = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(LiveAuthorityClockErrorV1::InvalidSample)?;
    LiveAuthorityClockSampleV1::new(linux_kernel_boot_commitment_v1(boot_before), value)
}

#[cfg(target_os = "linux")]
struct LiveClockNativeOriginalV1 {
    before: aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1,
    after: aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1,
    boottime: Option<rustix::time::Timespec>,
    result: Option<Result<LiveAuthorityClockSampleV1, LiveAuthorityClockErrorV1>>,
}

#[cfg(target_os = "linux")]
impl LiveClockNativeOriginalV1 {
    fn new() -> Self {
        Self { before: aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1::new(),
            after: aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1::new(),
            boottime: None, result: None }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.failure().or_else(|| self.after.failure())
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

#[cfg(target_os = "linux")]
struct RetainingLinuxLiveAuthorityClockV1 {
    original: Option<LiveClockNativeOriginalV1>,
}

#[cfg(target_os = "linux")]
impl LiveAuthorityClockSourceV1 for RetainingLinuxLiveAuthorityClockV1 {
    fn sample(&mut self) -> Result<LiveAuthorityClockSampleV1, LiveAuthorityClockErrorV1> {
        if self.original.as_ref().is_some_and(|original|
            original.result.as_ref().is_none_or(Result::is_err))
        {
            return Err(LiveAuthorityClockErrorV1::Unavailable);
        }
        // The preceding complete primitive has no native proof borrow: its
        // caller owns copied boot/time DATA. Refused/partial primitives never
        // reach this disposal boundary and remain resident without retry.
        drop(self.original.take());
        self.original = Some(LiveClockNativeOriginalV1::new());
        let original = self.original.as_mut().ok_or(LiveAuthorityClockErrorV1::Unavailable)?;
        let result = sample_linux_clock_engine_v1(Some(original));
        original.result = Some(result);
        result
    }

    fn native_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_ref()?.failure()
    }
}

#[cfg(target_os = "linux")]
pub(super) fn retaining_live_authority_clock_v1() -> FixedLiveAuthorityClockV1 {
    FixedLiveAuthorityClockV1 { source: Box::new(RetainingLinuxLiveAuthorityClockV1 { original: None }) }
}

#[cfg(target_os = "linux")]
pub(super) fn retained_live_clock_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
    let boot = aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?;
    let bytes = std::mem::size_of::<RetainingLinuxLiveAuthorityClockV1>()
        .checked_mul(2)?.checked_add(boot.checked_mul(2)?)?;
    Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
        .with(D::OpenFiles, 2))
}

/// Constructs the only clock implementation admitted by authority owners.
pub(crate) struct FixedLiveAuthorityClockV1 {
    source: Box<dyn LiveAuthorityClockSourceV1>,
}

impl FixedLiveAuthorityClockV1 {
    pub(crate) fn sample(
        &mut self,
    ) -> Result<LiveAuthorityClockSampleV1, LiveAuthorityClockErrorV1> {
        self.source.sample()
    }

    pub(super) fn native_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.native_failure()
    }
}

pub(crate) fn fixed_live_authority_clock_v1() -> FixedLiveAuthorityClockV1 {
    #[cfg(target_os = "linux")]
    {
        FixedLiveAuthorityClockV1 {
            source: Box::new(LinuxLiveAuthorityClockV1),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        FixedLiveAuthorityClockV1 {
            source: Box::new(UnavailableLiveAuthorityClockV1),
        }
    }
}

/// Verifies two live samples bracketed a protected operation on one boot.
///
/// # Errors
///
/// Returns [`LiveAuthorityClockErrorV1::InvalidSample`] for a boot change or
/// monotonic regression.
pub(crate) fn validate_bracketed_samples_v1(
    before: LiveAuthorityClockSampleV1,
    after: LiveAuthorityClockSampleV1,
) -> Result<LiveAuthorityClockSampleV1, LiveAuthorityClockErrorV1> {
    if before.boot() != after.boot() || before.boottime_nanoseconds() > after.boottime_nanoseconds()
    {
        return Err(LiveAuthorityClockErrorV1::InvalidSample);
    }
    Ok(after)
}
