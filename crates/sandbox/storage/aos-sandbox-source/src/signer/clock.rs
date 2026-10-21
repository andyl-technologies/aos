//! Preserves Source clock diagnostics over the sole Broker native sampler.

#[derive(Debug, thiserror::Error)]
pub(super) enum SourceClockErrorV1 {
    #[error("Source genesis owner or credential is not current")]
    Stale,
    #[error(transparent)]
    Kernel(#[from] aos_linux_descriptors::Error),
}

impl aos_sandbox_broker::kernel_clock::KernelPairedClockErrorV1 for SourceClockErrorV1 {
    fn stale() -> Self { Self::Stale }

    fn kernel(error: aos_linux_descriptors::Error) -> Self { Self::Kernel(error) }
}

pub(super) type SourceClockOriginalV1 =
    aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1<SourceClockErrorV1>;
