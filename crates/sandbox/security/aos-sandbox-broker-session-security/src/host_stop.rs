//! Retains the selected Stop request preparation on the existing Session engine.
//!
//! The original is inert and admits no effect. Its actual same-B caller pays
//! the complete fixed prefix before entry; the canonical request quote pays
//! dynamic history, signer, parser and append models separately.

use crate::recovery::ClientRequestOriginalsV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

/// Keeps the same request engine's native, partial parser and refusal custody.
#[derive(Default)]
#[must_use]
pub struct HostStopRequestPreparationOriginalV5 {
    pub(crate) request: ClientRequestOriginalsV1,
}

impl HostStopRequestPreparationOriginalV5 {
    /// Bounds the actual retained prefix before any selected preparation IO.
    #[must_use]
    pub fn receiving_demand_v5() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(ClientRequestOriginalsV1::receiving_backing_bytes_v1()?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, u64::try_from(
                ClientRequestOriginalsV1::retained_endpoint_open_files_v1()?).ok()?))
    }

    /// Borrows the actual reached native or parser cause without rebuilding it.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.request.failure()
    }
}
