//! Samples the sole existing kernel clock for an ordinary genesis flight.
//!
//! Neither a returned pair nor an age comparison creates a role grant. The
//! actual flight keeps its original deadline and independently owed posts.

use aos_sandbox_model::RawPairedClockSample;

use super::super::RootAuthorityErrorV1;

impl aos_sandbox_broker::kernel_clock::KernelPairedClockErrorV1 for RootAuthorityErrorV1 {
    fn stale() -> Self {
        Self::Stale
    }

    fn kernel(error: aos_linux_descriptors::Error) -> Self {
        Self::Kernel(error)
    }
}

pub(super) fn kernel_pair() -> Result<RawPairedClockSample, RootAuthorityErrorV1> {
    aos_sandbox_broker::kernel_clock::ordinary_kernel_pair()
}

pub(super) fn observe_original_clock(
    original: Option<RawPairedClockSample>,
) -> Result<RawPairedClockSample, RootAuthorityErrorV1> {
    let current = kernel_pair()?;
    aos_sandbox_broker::kernel_clock::require_original_clock(original, current)
}
