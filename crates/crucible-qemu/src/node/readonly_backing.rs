//! Connects a completed Node's original slot witness to its same QMP channel.
//!
//! The host verifies the exact live slot, actor decoder and retained original.
//! The channel receives only that closed observation. PID/start-time scalars,
//! caller budgets and an independently supplied cancellation contract cannot
//! authorize this path. Successful receipt and stream EOF certify RAM-only
//! bytes from an ordinary stop, not CPU/device state or physical eligibility.

use std::io;
use std::sync::Arc;

use crucible_linux_resource::host_supervision::HostOperationGuard;

use super::QemuNode;
use crate::{
    LinuxQemuAttemptHostOwner, OriginalActorAccountError, OriginalActorDecodeOwner,
    QmpReadOnlyBackingEvent, QmpReadOnlyBackingReceipt,
};

/// Preserves binding, real process-contract and owning export refusals.
///
/// A failed export retains its decoder keeper and independent original cause.
/// Native descriptor uncertainty still requires the same actor's physical
/// containment; dropping this error never proves monitor imports retired.
pub use crate::linux_attempt_host::OriginalBackingObservationError as QemuReadOnlyBackingError;

impl QemuNode {
    /// Exports all registered RAM bytes through this Node's original channel.
    ///
    /// The closed factory installs its move-only slot witness before Node
    /// exposure. This method verifies that witness against the supplied real
    /// host, decoder and original, then polls command and bytes concurrently.
    /// Each visitor slice is borrowed only for its callback. Callers retain any
    /// callback-owned diagnostics and physical original owners through failure.
    ///
    /// # Errors
    /// Refuses missing/stale/foreign authority, a cold or unsettled native stop,
    /// original cancellation, command or stream refusal, incomplete material,
    /// visitor failure, or disagreement between stream and typed receipt.
    pub fn capture_readonly_backing_under_original<'owner>(
        &mut self,
        host: &LinuxQemuAttemptHostOwner,
        decoder: &'owner OriginalActorDecodeOwner,
        original: &'owner Arc<HostOperationGuard>,
        visitor: &mut dyn for<'event> FnMut(QmpReadOnlyBackingEvent<'event>) -> io::Result<()>,
    ) -> Result<QmpReadOnlyBackingReceipt, QemuReadOnlyBackingError<'owner>> {
        let binding =
            self.original_native_binding
                .as_ref()
                .ok_or(QemuReadOnlyBackingError::Binding(
                    OriginalActorAccountError::Unavailable,
                ))?;
        let observation = host
            .bind_readonly_backing_observation(binding, decoder, original)
            .map_err(QemuReadOnlyBackingError::Binding)?;
        self.channels
            .qmp_machine_control
            .capture_readonly_backing(observation, visitor)
    }
}
