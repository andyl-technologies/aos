//! Owning failure returned by the consuming same-Root receiving handoff.
//!
//! The genuine original and every partial native result remain resident. Its
//! existing armed-drop contract requires intentional termination after failure.

use crate::controller_resource_reservation::RootReceivingOriginalV1;

/// Retains the original Root receiving owner after a failed startup handoff.
pub struct RootReceivingStartupFailureV1 {
    original: Box<RootReceivingOriginalV1>,
}

impl RootReceivingStartupFailureV1 {
    pub(crate) fn new(original: RootReceivingOriginalV1) -> Self {
        Self { original: Box::new(original) }
    }
}

impl std::fmt::Debug for RootReceivingStartupFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("RootReceivingStartupFailureV1").finish_non_exhaustive()
    }
}

impl std::fmt::Display for RootReceivingStartupFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("original Root receiving continuation failed")
    }
}

impl std::error::Error for RootReceivingStartupFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }
}
