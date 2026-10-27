//! Why a lifecycle boundary refuses an exact checkpoint, as diagnostics name it.
//!
//! The production lifecycle names the first blocking condition through
//! [`ProductionExactCheckpointNotReady`]. Lifecycle facades that can only
//! answer readiness as a boolean report an unnamed refusal instead, so a
//! diagnostic never invents a reason the lifecycle did not give.

use std::fmt;

use crucible_control_api::ProductionExactCheckpointNotReady;

/// Names why the current boundary cannot enter an exact checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QemuExactCheckpointRefusal {
    /// The production lifecycle named the first blocking condition.
    Named(ProductionExactCheckpointNotReady),
    /// The lifecycle reported only that the boundary is not ready.
    Unnamed,
}

impl QemuExactCheckpointRefusal {
    /// Returns the stable kebab-case token naming this refusal in diagnostics.
    #[must_use]
    pub const fn token(&self) -> &'static str {
        match self {
            Self::Named(reason) => reason.token(),
            Self::Unnamed => "unnamed",
        }
    }
}

impl fmt::Display for QemuExactCheckpointRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(reason) => reason.fmt(formatter),
            Self::Unnamed => formatter.write_str("the lifecycle named no readiness reason"),
        }
    }
}
