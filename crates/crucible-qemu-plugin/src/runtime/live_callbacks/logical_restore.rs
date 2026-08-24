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
        let applied_generation = self
            .logical_restore_continuation_generation
            .load(Ordering::Acquire);
        if applied_generation != request.generation {
            if applied_generation != 0 {
                return Err(
                    LiveVcpuTimeCallbackError::LogicalRestoreContinuationReused {
                        applied_generation,
                        requested_generation: request.generation,
                    },
                );
            }
            if let Some(network) = self.network.as_ref() {
                network.tx.restore_next_seq(network.restore_tx_sequence);
            }
            super::super::live_whitebox::restore_app_random_continuation().map_err(|source| {
                LiveVcpuTimeCallbackError::WhiteboxCallback {
                    message: source.to_string(),
                }
            })?;
            self.logical_restore_continuation_generation
                .store(request.generation, Ordering::Release);
        }
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
