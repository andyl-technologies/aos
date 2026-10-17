//! Settled control pause publication and inactive accepted-prefix effects.
//!
//! Original no-provider calls retain pause, shutdown and checkpoint-stop ordering.
//! The installed setup owner borrows its invocation-local native provider.
//! Busy preparation keeps the original request pending without publication or ACK.

use std::sync::atomic::Ordering;

use super::{
    IdleHotLoopError, LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState, PluginShmemOrdering,
    RegionControlAction, console_control,
};

pub(super) use super::console_effect::ConsoleControlEffect;

impl LiveVcpuTimeCallbackState {
    pub(super) fn publish_pause_for_boundary(
        &self,
        raw_icount: u64,
        checkpoint_handoff: bool,
        control_boundary_dispatch: bool,
        fingerprint_capture_request: Option<u32>,
        boundary: &'static str,
    ) -> Result<bool, LiveVcpuTimeCallbackError> {
        self.publish_pause_for_boundary_with_console(
            raw_icount,
            checkpoint_handoff,
            control_boundary_dispatch,
            fingerprint_capture_request,
            boundary,
            None,
        )
    }

    pub(super) fn publish_pause_for_boundary_with_console(
        &self,
        raw_icount: u64,
        checkpoint_handoff: bool,
        control_boundary_dispatch: bool,
        fingerprint_capture_request: Option<u32>,
        boundary: &'static str,
        mut console: Option<&mut console_control::ConsoleControlEffect<'_>>,
    ) -> Result<bool, LiveVcpuTimeCallbackError> {
        if let Some(console) = console.as_deref_mut() {
            // The common host claim also covers the physical restore release.
            // One bounded snapshot excludes an incomplete transaction before
            // reconstructing offsets or touching either original ACK.
            let Some(snapshot) = self.slot.get().try_snapshot() else {
                console.retain_pending();
                return Ok(true);
            };
            if snapshot.logical_time_restore_request != snapshot.logical_time_restore_ack {
                self.restore_logical_time_if_requested(raw_icount, false)?;
                if !console
                    .restore_prefix(
                        snapshot.logical_time_restore_request,
                        raw_icount,
                        snapshot.logical_time_restore_target,
                    )
                    .map_err(|source| LiveVcpuTimeCallbackError::ConsoleControl { source })?
                {
                    return Ok(true);
                }
            }
            // Native prefix reconciliation has already cleared its lexical
            // lease. Original restoration owns this physical ACK; the later
            // accepted-prefix writer and odd control ACK remain separate.
            self.restore_logical_time_if_requested(raw_icount, true)?;
        } else {
            self.restore_logical_time_if_requested(raw_icount, true)?;
        }
        match PluginShmemOrdering::observe_control_action(self.header.get()) {
            RegionControlAction::Shutdown => {
                self.signal_shared_shutdown()?;
                Ok(true)
            }
            RegionControlAction::Pause => {
                self.require_network_rx_commit_certain()?;

                // A paired control request owns checkpoint ordering. Its
                // eventfd callback first resumes device waiters, then invokes
                // the two-pass control boundary after their bottom halves are
                // visible. Futex, vCPU, and device callbacks must fence guest
                // progress but defer publication and native stop to that final
                // callback; stopping here can strand a newly active coroutine.
                if PluginShmemOrdering::control_boundary_is_requested(self.slot.get())
                    && !control_boundary_dispatch
                {
                    return Ok(true);
                }
                if PluginShmemOrdering::device_io_active(self.slot.get()) {
                    return Ok(true);
                }
                let previous_raw_icount = self.last_raw_icount.load(Ordering::Acquire);
                if raw_icount < previous_raw_icount {
                    return Err(LiveVcpuTimeCallbackError::IcountRegressed {
                        previous_icount: previous_raw_icount,
                        current_icount: raw_icount,
                    });
                }
                let current_icount = self.logical_icount_for_raw(raw_icount)?;
                let prepared_advance = if console.is_some() {
                    Some(
                        self.slot
                            .get()
                            .load_scheduler_advance_publication()
                            .map_err(|source| LiveVcpuTimeCallbackError::IdleHotLoop {
                                source: IdleHotLoopError::AdvanceStopCondition { source },
                            })?,
                    )
                } else {
                    None
                };
                let ceiling_icount = match prepared_advance {
                    Some(advance) => advance.ceiling(),
                    None => self.scheduler_advance()?.0,
                };
                if current_icount > ceiling_icount {
                    return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                        current_icount,
                        ceiling_icount,
                    });
                }
                let private_capture = if console.is_some() {
                    if let Some(capture_request) = fingerprint_capture_request {
                        self.capture_fingerprint_sample(current_icount, boundary)?
                            .map(|captured| (captured, capture_request))
                    } else {
                        None
                    }
                } else {
                    if let Some(capture_request) = fingerprint_capture_request {
                        self.publish_fingerprint_sample(current_icount, boundary, capture_request)?;
                    }
                    None
                };
                if let Some(console) = console {
                    let advance =
                        prepared_advance.ok_or(LiveVcpuTimeCallbackError::ConsoleControl {
                            source: crucible_protocol::native_console::NativeConsoleError::Binding,
                        })?;
                    let published = console
                        .publish_pause(self.slot.get(), current_icount, raw_icount, advance)
                        .map_err(|error| match error {
                            crucible_shmem::NodeBoundaryPublicationError::Slot(source) => {
                                LiveVcpuTimeCallbackError::PublishPause { source }
                            }
                            crucible_shmem::NodeBoundaryPublicationError::Effect(source) => {
                                LiveVcpuTimeCallbackError::ConsoleControl { source }
                            }
                        })?;
                    if !published {
                        return Ok(true);
                    }
                } else {
                    PluginShmemOrdering::publish_pause_quiesced(
                        self.slot.get(),
                        current_icount,
                        raw_icount,
                    )
                    .map_err(|source| LiveVcpuTimeCallbackError::PublishPause { source })?;
                }
                if let Some((captured, capture_request)) = private_capture {
                    // The actual writer has closed and released native custody.
                    // Only this enqueue lets the worker publish/ACK the capture.
                    self.submit_fingerprint_sample(captured, capture_request)?;
                }
                self.last_raw_icount.store(raw_icount, Ordering::Release);
                self.last_icount.store(current_icount, Ordering::Release);
                if checkpoint_handoff {
                    self.request_checkpoint_vmstop(boundary)?;
                }
                Ok(true)
            }
            RegionControlAction::Continue => Ok(false),
        }
    }
}
