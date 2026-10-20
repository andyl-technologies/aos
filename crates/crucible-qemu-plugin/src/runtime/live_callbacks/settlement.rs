//! Bounded-ceiling settlement callbacks for the sim loop.
//!
//! A published ceiling is an upper bound (RFC-0010 SCHED-12). QEMU stops a node
//! at its last retirement at or below the ceiling and may move the clock past
//! that retirement only to an exact event: a guest timer, which QEMU owns, or
//! one of the plugin-owned events reported here. When nothing remains before
//! the ceiling, QEMU publishes the reached icount through the settled callback
//! and the node slot records the settlement for the host.

use super::*;

impl LiveVcpuTimeCallbackState {
    /// Returns the earliest plugin-owned exact event in logical ticks.
    ///
    /// The candidates are the inbound ring head, the host-published device
    /// completion deadline while device I/O is active, and the ceiling itself
    /// when the host declared it an exact event. QEMU combines this with its
    /// own timer deadlines and ignores events at or before the current clock or
    /// past the ceiling.
    pub(super) fn exact_event_tick(&self) -> Result<u64, LiveVcpuTimeCallbackError> {
        let (ceiling_icount, stop_condition) = self.scheduler_advance()?;
        let mut earliest = if stop_condition == AdvanceStopCondition::ExactEvent {
            ceiling_icount
        } else {
            u64::MAX
        };

        if let Some(network) = self.network.as_ref()
            && let Some(delivery_icount) =
                PluginInboundFrames::peek_next_delivery_icount([network.inbound.inbound()])
                    .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?
        {
            earliest = earliest.min(delivery_icount);
        }

        let slot = self.slot.get();
        if PluginShmemOrdering::device_io_active(slot) {
            // Zero means the host has not published a completion deadline yet.
            let deadline = PluginShmemOrdering::device_completion_deadline_tick(slot);
            if deadline != 0 {
                earliest = earliest.min(deadline);
            }
        }
        Ok(earliest)
    }
}

/// Publishes a sim-loop boundary that QEMU settled through `settled_ceiling`.
pub(super) extern "C" fn crucible_qemu_plugin_live_publish_settled_cb(
    raw_icount: u64,
    settled_ceiling: u64,
    userdata: *mut c_void,
) {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return;
    };
    let result = state
        .publish_boundary_icount(
            raw_icount,
            true,
            "sim-settled-publication",
            Some(settled_ceiling),
        )
        .and_then(|()| state.request_selectable_vmstop_if_pending(raw_icount));
    if let Err(error) = result {
        abort_live_callback(error);
    }
}

/// Reports the earliest plugin-owned exact event, or `u64::MAX` when none is
/// pending or the runtime is tearing down.
pub(super) extern "C" fn crucible_qemu_plugin_live_exact_event_tick_cb(
    userdata: *mut c_void,
) -> u64 {
    let state = callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        return u64::MAX;
    };
    match state.exact_event_tick() {
        Ok(tick) => tick,
        Err(error) => abort_live_callback(error),
    }
}
