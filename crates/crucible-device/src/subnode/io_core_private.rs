//! Private request-computation helpers for [`IoCore`].

use super::*;

impl IoCore {
    /// COMPUTEs one request and inserts its response in delivery order.
    pub(super) fn compute_request<D>(
        &mut self,
        device: &mut D,
        request: Request,
    ) -> Result<(), DeviceError>
    where
        D: IoSubNode,
    {
        let delivery_icount = self.compute_delivery_icount(&request, device.latency_model())?;
        let current_icount = self.clock.current_icount();
        if delivery_icount < current_icount {
            return Err(DeviceError::DeliveryInPast {
                delivery_icount,
                current_icount,
            });
        }
        let response = device.compute(&request)?;
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let key = FrameDeliveryKey {
            delivery_icount,
            src_node: self.src_node,
            seq,
        };
        self.inflight.insert(PendingResponse::new(key, response));
        Ok(())
    }

    /// Re-inserts a pending response and the remaining due responses in order.
    pub(super) fn requeue_pending(
        &mut self,
        pending: PendingResponse,
        remaining: impl IntoIterator<Item = PendingResponse>,
    ) {
        self.inflight.insert(pending);
        for pending in remaining {
            self.inflight.insert(pending);
        }
    }
}
