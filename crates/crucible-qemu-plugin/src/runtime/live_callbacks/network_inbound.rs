//! Guest RX acceptance, exact original-head settlement, and containment joins.
//!
//! These methods share the registered live runtime but retain network ingress
//! custody independently from vCPU timing and device callback publication.

use super::*;

impl LiveVcpuTimeCallbackState {
    /// Injects and commits every router frame due at this guest boundary.
    ///
    /// The plugin is the only consumer of the router-to-VM SPSC ring. The host
    /// may observe the consumer index after a release-published boundary, but it
    /// must never dequeue a payload. Each accepted head is committed before the
    /// next guest callback, so a later delivery failure cannot replay an earlier
    /// guest acceptance. Reentrant delivery remains excluded for the whole pass.
    pub(super) fn inject_due_network_inbound(
        &self,
        current_icount: u64,
        passed_delivery_floor_icount: u64,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let Some(network) = self.network.as_ref() else {
            return Ok(());
        };
        if network
            .rx_delivery_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // Direct QEMU RX can synchronously re-enter a progress callback.
            // The outer attempt still owns the canonical ring head, so the
            // nested callback must not deliver that same frame recursively.
            return Ok(());
        }
        let _active = NetworkRxDeliveryActiveGuard(&network.rx_delivery_active);
        let preview = {
            let inbound = network.inbound.inbound();
            PluginInboundFrames::preview_deliverable_since(
                [inbound],
                current_icount,
                passed_delivery_floor_icount,
            )
            .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?
        };
        if let Some(first) = preview.frames().first() {
            let original_head = self
                .network_inbound_head_observe()?
                .ok_or(LiveVcpuTimeCallbackError::InboundCommitMismatch)?;
            if original_head.frame != *first
                || !self.network_inbound_head_current(&original_head)?
            {
                return Err(LiveVcpuTimeCallbackError::InboundCommitMismatch);
            }
        }
        let injection = if preview.frames().is_empty() {
            None
        } else {
            let mut rx_queue = network.rx_queue;
            Some(
                crate::network_rx::handle_network_rx_idle_callback_with_commit(
                    &network.rx,
                    &mut rx_queue,
                    passed_delivery_floor_icount,
                    current_icount,
                    preview.frames(),
                    |frame| {
                        PluginInboundFrames::commit_delivered_prefix(
                            [network.inbound.inbound()],
                            current_icount,
                            std::slice::from_ref(frame),
                        )
                        .map(|_| ())
                    },
                )
                .map_err(|source| LiveVcpuTimeCallbackError::NetworkRx { source })?,
            )
        };
        let delivered_count = injection
            .as_ref()
            .map_or(0, |result| result.delivered_frame_keys().len());
        let delivered_frames = &preview.frames()[..delivered_count];
        if injection.as_ref().is_some_and(|result| {
            result.delivered_frame_keys()
                != delivered_frames
                    .iter()
                    .map(FrameEntry::delivery_key)
                    .collect::<Vec<_>>()
        }) {
            return Err(LiveVcpuTimeCallbackError::InboundCommitMismatch);
        }
        if let Some(retained) = injection.and_then(|result| result.retained_frame_key()) {
            let inbound = network.inbound.inbound();
            PluginInboundFrames::mark_retained_head([inbound], retained, current_icount)
                .map_err(|source| LiveVcpuTimeCallbackError::InboundFrames { source })?;
        }
        Ok(())
    }

    /// Refuses checkpoint handoff after an ambiguous guest RX ownership transfer.
    pub(in crate::runtime) fn network_rx_commit_uncertain(&self) -> bool {
        self.network
            .as_ref()
            .is_some_and(|network| network.rx.commit_uncertain())
    }

    pub(super) fn require_network_rx_commit_certain(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        if self.network_rx_commit_uncertain() {
            return Err(LiveVcpuTimeCallbackError::NetworkRx {
                source: crate::NetworkRxError::CommitUncertain,
            });
        }

        Ok(())
    }

    /// Observes only the registered network ring's exact live head.
    pub(crate) fn network_inbound_head_observe(
        &self,
    ) -> Result<Option<NetworkInboundHeadObservation>, LiveVcpuTimeCallbackError> {
        self.network
            .as_ref()
            .map_or(Ok(None), LiveNetworkCallbackState::inbound_head_observe)
    }

    /// Checks the original owner generation, read frontier, and full head.
    pub(crate) fn network_inbound_head_current(
        &self,
        original: &NetworkInboundHeadObservation,
    ) -> Result<bool, LiveVcpuTimeCallbackError> {
        self.network
            .as_ref()
            .map_or(Ok(false), |network| network.inbound_head_current(original))
    }

}
