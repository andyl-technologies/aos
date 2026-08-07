//! Private request-computation helpers for [`IoCore`].

use super::*;

impl IoCore {
    pub(super) fn insert_computed_at_nanos(
        &mut self,
        base_completion_nanos: u64,
        computed: ComputedResponse,
    ) -> Result<(), DeviceError> {
        if computed.primary.is_none() && !computed.additional.is_empty() {
            return Err(DeviceError::InvalidComputedResponse);
        }
        let Some(primary) = computed.primary else {
            return Ok(());
        };
        let primary_nanos = base_completion_nanos
            .checked_add(computed.additional_latency_nanos)
            .ok_or(DeviceError::CompletionOverflow {
                request_icount: self.clock.current_icount(),
                latency_ns: computed.additional_latency_nanos,
            })?;
        let delivery_icount = self.clock.ceil_ns_to_icount(primary_nanos)?;
        if delivery_icount < self.clock.current_icount() {
            return Err(DeviceError::DeliveryInPast {
                delivery_icount,
                current_icount: self.clock.current_icount(),
            });
        }
        let response_count = u32::try_from(computed.additional.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(DeviceError::ResponseSequenceOverflow {
                sequence: self.next_seq,
            })?;
        self.next_seq
            .checked_add(response_count)
            .ok_or(DeviceError::ResponseSequenceOverflow {
                sequence: self.next_seq,
            })?;
        let mut prepared = Vec::with_capacity(computed.additional.len() + 1);
        prepared.push((delivery_icount, primary));
        for additional in computed.additional {
            let nanos = primary_nanos.checked_add(additional.gap_nanos).ok_or(
                DeviceError::CompletionOverflow {
                    request_icount: self.clock.current_icount(),
                    latency_ns: computed
                        .additional_latency_nanos
                        .saturating_add(additional.gap_nanos),
                },
            )?;
            prepared.push((self.clock.ceil_ns_to_icount(nanos)?, additional.response));
        }
        for (delivery_icount, response) in prepared {
            self.insert_computed_response(delivery_icount, response)?;
        }
        Ok(())
    }

    /// COMPUTEs one request and inserts its response in delivery order.
    pub(super) fn compute_request<D>(
        &mut self,
        device: &mut D,
        request: Request,
    ) -> Result<(), DeviceError>
    where
        D: IoSubNode,
    {
        let base_ns = self.clock.virtual_ns(request.request_icount)?;
        let latency_ns = device.latency_model().latency_ns(&request);
        let immutable_completion_ns =
            base_ns
                .checked_add(latency_ns)
                .ok_or(DeviceError::CompletionOverflow {
                    request_icount: request.request_icount,
                    latency_ns,
                })?;
        let immutable_delivery_icount = self.clock.ceil_ns_to_icount(immutable_completion_ns)?;
        let current_icount = self.clock.current_icount();
        if immutable_delivery_icount < current_icount {
            return Err(DeviceError::DeliveryInPast {
                delivery_icount: immutable_delivery_icount,
                current_icount,
            });
        }

        let checkpoint = device.compute_checkpoint();
        let computed = match device.compute(&request) {
            Ok(computed) => computed,
            Err(error) => {
                device.restore_compute_checkpoint(checkpoint);
                return Err(error);
            }
        };
        let prepared = (|| {
            if computed.primary.is_none() && !computed.additional.is_empty() {
                return Err(DeviceError::InvalidComputedResponse);
            }
            let Some(primary) = computed.primary else {
                return Ok(Vec::new());
            };
            let primary_ns = immutable_completion_ns
                .checked_add(computed.additional_latency_nanos)
                .ok_or(DeviceError::CompletionOverflow {
                    request_icount: request.request_icount,
                    latency_ns: latency_ns.saturating_add(computed.additional_latency_nanos),
                })?;
            let delivery_icount = self.clock.ceil_ns_to_icount(primary_ns)?;
            if delivery_icount < current_icount {
                return Err(DeviceError::DeliveryInPast {
                    delivery_icount,
                    current_icount,
                });
            }
            let response_count = u32::try_from(computed.additional.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or(DeviceError::ResponseSequenceOverflow {
                    sequence: self.next_seq,
                })?;
            self.next_seq.checked_add(response_count).ok_or(
                DeviceError::ResponseSequenceOverflow {
                    sequence: self.next_seq,
                },
            )?;
            let mut responses = Vec::with_capacity(computed.additional.len() + 1);
            responses.push((delivery_icount, primary));
            for additional in computed.additional {
                let additional_ns = primary_ns.checked_add(additional.gap_nanos).ok_or(
                    DeviceError::CompletionOverflow {
                        request_icount: request.request_icount,
                        latency_ns: latency_ns
                            .saturating_add(computed.additional_latency_nanos)
                            .saturating_add(additional.gap_nanos),
                    },
                )?;
                responses.push((
                    self.clock.ceil_ns_to_icount(additional_ns)?,
                    additional.response,
                ));
            }
            Ok(responses)
        })();
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                device.restore_compute_checkpoint(checkpoint);
                return Err(error);
            }
        };
        for (delivery_icount, response) in prepared {
            self.insert_computed_response(delivery_icount, response)?;
        }
        Ok(())
    }

    pub(super) fn insert_computed_response(
        &mut self,
        delivery_icount: u64,
        response: Response,
    ) -> Result<(), DeviceError> {
        let seq = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(DeviceError::ResponseSequenceOverflow { sequence: seq })?;
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
