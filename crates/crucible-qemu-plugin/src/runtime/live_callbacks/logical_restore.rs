//! Logical-time restoration at exact VMState callback boundaries.

use std::sync::atomic::Ordering;

use super::{LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState};
use crate::PluginShmemOrdering;

pub(super) fn raw_icount_publication_is_superseded(
    raw_icount_at_entry: u64,
    raw_icount: u64,
    latest_raw_icount: u64,
) -> Result<bool, LiveVcpuTimeCallbackError> {
    if raw_icount < raw_icount_at_entry {
        return Err(LiveVcpuTimeCallbackError::IcountRegressed {
            previous_icount: raw_icount_at_entry,
            current_icount: raw_icount,
        });
    }

    Ok(raw_icount < latest_raw_icount)
}

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
            super::super::live_whitebox::restore_selectable_continuation().map_err(|source| {
                LiveVcpuTimeCallbackError::WhiteboxCallback {
                    message: source.to_string(),
                }
            })?;
            crate::coverage::reset_live_coverage_for_restore(request.generation)
                .map_err(|source| LiveVcpuTimeCallbackError::CoverageRestore { source })?;
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
        if acknowledge_boundary {
            PluginShmemOrdering::acknowledge_logical_time_restore(
                self.slot.get(),
                request,
                request.target_icount,
                raw_icount,
            )
            .map_err(|source| LiveVcpuTimeCallbackError::PublishPause { source })?;
        }
        Ok(())
    }
}
