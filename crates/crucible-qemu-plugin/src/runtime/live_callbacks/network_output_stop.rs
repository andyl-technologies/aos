//! Original output-stop intent retained until the registered TX consumer settles.
//!
//! Native stop admission is asynchronous. Resume, idle, and progress callbacks
//! preserve the original device coordinate until its output is consumed. A
//! nonblocking mutex joins callbacks that need not share the BQL or RR owner;
//! no guard crosses native admission or another callback-capable native operation.
//! Read-only sim-clock observation does not invoke callbacks.

use super::*;

pub(super) mod context;

pub(super) use context::ArmOrigin;

/// Original device coordinate and exact registered producer frontier.
#[derive(Clone)]
pub(super) struct RetainedNetworkOutputStop {
    logical_icount: u64,
    raw_icount: u64,
    write_index: u64,
    context: Option<Arc<context::ArmContext>>,
}

impl RetainedNetworkOutputStop {
    /// Records the SDK return on this arm's independent diagnostic object.
    pub(super) fn observe_admission(&self, status: i32) {
        if let Some(context) = self.context.as_ref() {
            context.observe_admission(status);
        }
    }
}

impl LiveNetworkCallbackState {
    fn try_output_stop(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, Option<RetainedNetworkOutputStop>>,
        LiveVcpuTimeCallbackError,
    > {
        let status = self.output_stop_refusal.load(Ordering::Acquire);
        if status != 0 {
            return Err(LiveVcpuTimeCallbackError::CheckpointVmStopRejected {
                boundary: "network-output",
                status,
            });
        }
        match self.output_stop.try_lock() {
            Ok(stop) => Ok(stop),
            Err(TryLockError::WouldBlock) => {
                Err(LiveVcpuTimeCallbackError::NetworkOutputStopBorrowed)
            }
            Err(TryLockError::Poisoned(_error)) => {
                Err(LiveVcpuTimeCallbackError::CallbackStatePoisoned)
            }
        }
    }

    fn unconsumed_output_stop(
        &self,
        stop: &mut Option<RetainedNetworkOutputStop>,
    ) -> Result<Option<RetainedNetworkOutputStop>, LiveVcpuTimeCallbackError> {
        let Some(retained) = stop.as_ref() else {
            return Ok(None);
        };
        let write_index = PluginShmemOrdering::producer_write_index(self.outbound.header());
        if write_index != retained.write_index {
            return Err(
                LiveVcpuTimeCallbackError::NetworkOutputStopFrontierChanged {
                    write_index: retained.write_index,
                    observed_write_index: write_index,
                },
            );
        }
        if PluginShmemOrdering::consumer_read_index(self.outbound.header()) == retained.write_index
        {
            // Only the original consumer can settle this exact frontier. A
            // new ceiling, callback, or diagnostic notice cannot retire it.
            *stop = None;
        }
        Ok(stop.clone())
    }
}

impl LiveVcpuTimeCallbackState {
    /// Requests QEMU's native stopped runstate after publishing the boundary.
    pub(super) fn request_checkpoint_vmstop(
        &self,
        boundary: &'static str,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        self.request_checkpoint_vmstop_observed(boundary, None)
    }

    fn request_checkpoint_vmstop_observed(
        &self,
        boundary: &'static str,
        original: Option<network_output_stop::RetainedNetworkOutputStop>,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let notice = self.capture_stop_caller(
            boundary,
            original
                .as_ref()
                .map(|stop| (stop.raw_icount, stop.logical_icount)),
        );
        self.notice_stop_before(notice);
        let status = (self.request_vmstop)();
        self.notice_stop_after(notice, status);
        if let Some(original) = original {
            original.observe_admission(status);
        }
        // Multiple exact callbacks can observe the same level-triggered pause
        // before QEMU's main loop consumes the first admitted stop request.
        // QEMU reports that race as -EALREADY; the required stop is already
        // fenced and queued, so this callback has satisfied its handoff too.
        const NEGATIVE_EALREADY: i32 = -114;
        if status == 0 || status == NEGATIVE_EALREADY {
            Ok(())
        } else {
            Err(LiveVcpuTimeCallbackError::CheckpointVmStopRejected { boundary, status })
        }
    }

    /// Fences the exact output coordinate before native dispatch can continue.
    pub(super) fn request_network_output_stop(
        &self,
        original: network_output_stop::RetainedNetworkOutputStop,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let admission = self.request_checkpoint_vmstop_observed("network-output", Some(original));
        if let Err(LiveVcpuTimeCallbackError::CheckpointVmStopRejected { status, .. }) = &admission
        {
            self.retain_network_output_stop_refusal(*status);
        }
        admission
    }

    pub(super) fn preserve_network_output_stop(
        &self,
        raw_icount: u64,
        phase: &'static str,
    ) -> Result<bool, LiveVcpuTimeCallbackError> {
        let Some(network) = self.network.as_ref() else {
            return Ok(false);
        };
        let mut owner = network.try_output_stop()?;
        let Some(stop) = network.unconsumed_output_stop(&mut owner)? else {
            return Ok(false);
        };
        // Observation is read-only here. A mismatching callback must not
        // recalibrate the logical offset before its original coordinate refuses.
        let logical_icount = if let Some(observe_tick) = self.sim_tick_observed {
            let observed_tick = observe_tick();
            u64::try_from(observed_tick).map_err(|_error| {
                LiveVcpuTimeCallbackError::InvalidSimTickObservation { observed_tick }
            })?
        } else {
            self.logical_icount_for_raw(raw_icount)?
        };
        validate_original_coordinate(&stop, logical_icount, raw_icount, phase)?;
        PluginShmemOrdering::publish_pause_quiesced(
            self.slot.get(),
            stop.logical_icount,
            stop.raw_icount,
        )
        .map_err(|source| LiveVcpuTimeCallbackError::PublishPause { source })?;
        Ok(true)
    }

    pub(super) fn begin_network_output_stop(
        &self,
        logical_icount: u64,
        raw_icount: u64,
        phase: &'static str,
    ) -> Result<
        std::sync::MutexGuard<'_, Option<RetainedNetworkOutputStop>>,
        LiveVcpuTimeCallbackError,
    > {
        let network = self
            .network
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::NetworkStateUnavailable)?;
        let mut owner = network.try_output_stop()?;
        if let Some(stop) = network.unconsumed_output_stop(&mut owner)? {
            validate_original_coordinate(&stop, logical_icount, raw_icount, phase)?;
        }
        Ok(owner)
    }

    pub(super) fn finish_network_output_stop(
        &self,
        owner: &mut Option<RetainedNetworkOutputStop>,
        logical_icount: u64,
        raw_icount: u64,
        origin: ArmOrigin,
    ) -> Result<RetainedNetworkOutputStop, LiveVcpuTimeCallbackError> {
        let network = self
            .network
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::NetworkStateUnavailable)?;
        let write_index = PluginShmemOrdering::producer_write_index(network.outbound.header());
        PluginShmemOrdering::publish_pause_quiesced(self.slot.get(), logical_icount, raw_icount)
            .map_err(|source| LiveVcpuTimeCallbackError::PublishPause { source })?;
        let stop = RetainedNetworkOutputStop {
            logical_icount,
            raw_icount,
            write_index,
            context: context::ArmContext::new(self.control_callback_witness.is_enabled(), origin),
        };
        *owner = Some(stop.clone());
        Ok(stop)
    }

    pub(super) fn retain_network_output_stop_refusal(&self, status: i32) {
        if let Some(network) = self.network.as_ref() {
            // Retain the first admission error even if another callback owns
            // the mutex. Neither a later borrow nor consumption can replace it.
            let _prior = network.output_stop_refusal.compare_exchange(
                0,
                status,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }

    pub(super) fn require_consumed_network_output_stop(
        &self,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let Some(network) = self.network.as_ref() else {
            return Ok(());
        };
        let mut owner = network.try_output_stop()?;
        if let Some(stop) = network.unconsumed_output_stop(&mut owner)? {
            return Err(LiveVcpuTimeCallbackError::NetworkOutputStopUnconsumed {
                write_index: stop.write_index,
                read_index: PluginShmemOrdering::consumer_read_index(network.outbound.header()),
            });
        }
        Ok(())
    }
}

fn validate_original_coordinate(
    stop: &RetainedNetworkOutputStop,
    logical_icount: u64,
    raw_icount: u64,
    phase: &'static str,
) -> Result<(), LiveVcpuTimeCallbackError> {
    if raw_icount != stop.raw_icount || logical_icount != stop.logical_icount {
        context::report_failure(stop, logical_icount, raw_icount, phase);
        return Err(LiveVcpuTimeCallbackError::NetworkOutputStopProgressed {
            logical_icount: stop.logical_icount,
            raw_icount: stop.raw_icount,
            observed_logical_icount: logical_icount,
            observed_raw_icount: raw_icount,
        });
    }
    Ok(())
}
