//! Retains a controller's first provider refusal in its prelaunch allocation.
//!
//! Erased observers keep the independent finalizer alive. The cause allocation
//! closes before its error payload and the final accounting observer are dropped.

use std::fmt;
use std::sync::OnceLock;

use crucible_engine::SharedOperationalCause;
use crucible_qemu_protocol::ram_control::RamControlError;

use super::RetainedCleanupFinalizer;

#[derive(Debug)]
pub(crate) struct ControllerReturnCause {
    first: OnceLock<RamControlError>,
    // This last field keeps accounting live through the actual error's close.
    _finalizer: RetainedCleanupFinalizer,
}

impl ControllerReturnCause {
    pub(super) fn new(finalizer: RetainedCleanupFinalizer) -> Self {
        Self {
            first: OnceLock::new(),
            _finalizer: finalizer,
        }
    }

    pub(crate) fn retain(&self, first: RamControlError) {
        self.first.get_or_init(|| first);
    }

    /// Covers the allocation and overlapping construction/return frames.
    pub(super) fn peak_bytes() -> Option<u64> {
        SharedOperationalCause::<Self>::allocation_bytes()
            .ok()?
            .checked_add(std::mem::size_of::<Self>())?
            .checked_add(std::mem::size_of::<SharedOperationalCause<Self>>())?
            .checked_add(std::mem::size_of::<RamControlError>())?
            .try_into()
            .ok()
    }
}

impl fmt::Display for ControllerReturnCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.first.get() {
            Some(first) => first.fmt(formatter),
            None => formatter.write_str("controller return has no provider refusal"),
        }
    }
}

impl std::error::Error for ControllerReturnCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.first
            .get()
            .map(|first| first as &dyn std::error::Error)
    }
}
