//! Logical-time restoration at exact VMState callback boundaries.

use std::sync::atomic::Ordering;

use super::{LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState};
use crate::PluginShmemOrdering;

impl LiveVcpuTimeCallbackState {
    /// Reconstructs the plugin-local idle-jump offset after VMState load.
    pub(super) fn restore_logical_time_if_requested(
        &self,
        raw_icount: u64,
        acknowledge_boundary: bool,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let Some(request) = PluginShmemOrdering::pending_logical_time_restore(self.slot.get())
        else {
            return Ok(());
        };
        let offset = request.target_icount.checked_sub(raw_icount).ok_or(
            LiveVcpuTimeCallbackError::InitialRawIcountBeyondLogical {
                raw_icount,
                logical_icount: request.target_icount,
            },
        )?;
        self.logical_icount_offset.store(offset, Ordering::Release);
        self.last_raw_icount.store(raw_icount, Ordering::Release);
        self.last_icount
            .store(request.target_icount, Ordering::Release);
        if let Some(fingerprint) = self.fingerprint.as_ref() {
            // A fresh QEMU generation may have sampled the throwaway boot
            // barrier priming state at the same coordinate as the restored
            // VMState. Force the following exact pause to capture the loaded
            // registers, RAM, and devices rather than retaining that sample.
            fingerprint
                .capture_submitted
                .store(false, Ordering::Release);
        }
        if acknowledge_boundary {
            PluginShmemOrdering::acknowledge_logical_time_restore(
                self.slot.get(),
                request,
                request.target_icount,
                raw_icount,
                self.icount_shift,
            )
            .map_err(|source| LiveVcpuTimeCallbackError::PublishPause { source })?;
        }
        Ok(())
    }
}
