//! Backend construction failures retaining their original cleanup authority.
//!
//! Cloning a lifecycle error shares the actual cause. RPC serialization may
//! render a diagnostic, while the in-process error keeps native failure and
//! launch-input custody until its final owner drops.

use crucible_engine::BackendOperationalCause;
use std::error::Error;
use std::fmt;

/// A shared backend construction failure with its original typed cause.
#[derive(Clone, Debug)]
pub struct LifecycleBackendConstructionError {
    source: BackendOperationalCause,
}

impl LifecycleBackendConstructionError {
    /// Retains an existing closed backend cause without another allocation.
    ///
    /// The final observer frees its shared control before destroying the
    /// concrete error and any original loans it retains. The original payer
    /// still covers every owned payload and physical cleanup obligation; this
    /// method creates no resource entitlement or backend operation.
    #[must_use]
    pub fn from_operational(source: BackendOperationalCause) -> Self {
        Self { source }
    }

    /// Shares a newly owned typed backend-construction failure.
    ///
    /// The caller accounts for the actual shared allocation before calling.
    #[must_use]
    pub fn new(source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            source: BackendOperationalCause::new(source),
        }
    }
}

impl PartialEq for LifecycleBackendConstructionError {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for LifecycleBackendConstructionError {}

impl fmt::Display for LifecycleBackendConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for LifecycleBackendConstructionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.source()
    }
}
