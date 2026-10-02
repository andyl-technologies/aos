//! Original output-stop intent retained until the registered TX consumer settles.
//!
//! Native stop admission is asynchronous. Resume, idle, and progress callbacks
//! preserve the original device coordinate until its output is consumed. A
//! nonblocking mutex joins callbacks that need not share the BQL or RR owner;
//! no guard crosses native admission or another callback-capable native operation.
//! Read-only sim-clock observation does not invoke callbacks.

use super::*;

/// Original device coordinate and exact registered producer frontier.
#[derive(Clone, Copy)]
pub(super) struct RetainedNetworkOutputStop {
    logical_icount: u64,
    raw_icount: u64,
    write_index: u64,
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
        let Some(retained) = *stop else {
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
        Ok(*stop)
    }
}

impl LiveVcpuTimeCallbackState {
    pub(super) fn preserve_network_output_stop(
        &self,
        raw_icount: u64,
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
        validate_original_coordinate(stop, logical_icount, raw_icount)?;
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
            validate_original_coordinate(stop, logical_icount, raw_icount)?;
        }
        Ok(owner)
    }

    pub(super) fn finish_network_output_stop(
        &self,
        owner: &mut Option<RetainedNetworkOutputStop>,
        logical_icount: u64,
        raw_icount: u64,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let network = self
            .network
            .as_ref()
            .ok_or(LiveVcpuTimeCallbackError::NetworkStateUnavailable)?;
        let write_index = PluginShmemOrdering::producer_write_index(network.outbound.header());
        PluginShmemOrdering::publish_pause_quiesced(self.slot.get(), logical_icount, raw_icount)
            .map_err(|source| LiveVcpuTimeCallbackError::PublishPause { source })?;
        *owner = Some(RetainedNetworkOutputStop {
            logical_icount,
            raw_icount,
            write_index,
        });
        Ok(())
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
    stop: RetainedNetworkOutputStop,
    logical_icount: u64,
    raw_icount: u64,
) -> Result<(), LiveVcpuTimeCallbackError> {
    if raw_icount != stop.raw_icount || logical_icount != stop.logical_icount {
        return Err(LiveVcpuTimeCallbackError::NetworkOutputStopProgressed {
            logical_icount: stop.logical_icount,
            raw_icount: stop.raw_icount,
            observed_logical_icount: logical_icount,
            observed_raw_icount: raw_icount,
        });
    }
    Ok(())
}
