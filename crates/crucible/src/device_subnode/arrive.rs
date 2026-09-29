//! Complete modeled ARRIVE collection before canonical device COMPUTE.
//!
//! Host collection order is not an input to a modeled phase. The actor supplies
//! its complete set before COMPUTE, and the adapter allocates original response
//! sequences by exact request tick and full transport identity. Live FIFO input
//! and already-computed or restored response keys are never reordered here.

use super::*;

impl DeviceSchedulingSubNode {
    /// Computes one complete modeled ARRIVE phase in canonical request order.
    ///
    /// `arrivals` is the actor's complete device request set for this phase,
    /// collected before any COMPUTE. Ordering by `(request_icount, epoch,
    /// request_id)` precedes response sequence allocation and device effects.
    /// Distinct arrivals cannot share that full identity at the same tick.
    ///
    /// The method retains no hidden uncomputed queue and never renumbers an
    /// existing completion. Live input with an authoritative FIFO order uses
    /// [`Self::submit_fifo`].
    ///
    /// # Errors
    ///
    /// Refuses an ambiguous arrival set or non-block device before COMPUTE.
    /// Device errors retain the already-computed canonical prefix; the caller
    /// must contain the failed modeled phase rather than retry its entire set.
    pub fn submit_arrivals(
        &mut self,
        mut arrivals: Vec<(u64, BlockRequest)>,
    ) -> Result<(), DeviceError> {
        if !matches!(self.device, ScheduledDevice::Block(_)) {
            return Err(DeviceError::WrongDeviceKind {
                expected: "block",
                actual: "9p",
            });
        }
        arrivals.sort_by_key(|(tick, request)| (*tick, request.identity()));
        if arrivals
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0 && pair[0].1.identity() == pair[1].1.identity())
        {
            return Err(DeviceError::AmbiguousModeledArrival);
        }

        for (tick, request) in arrivals {
            self.submit_fifo(tick, &request)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> DeviceSchedulingSubNode {
        let core = IoCore::new(7, 16, 16).unwrap_or_else(|error| panic!("model queue: {error}"));
        DeviceSchedulingSubNode::new(
            SchedulerNodeId {
                node: NodeId {
                    name: "disk".into(),
                },
                kind: crate::SchedulingNodeKind::Disk,
            },
            NodeId { name: "vm".into() },
            DeviceId {
                name: "disk".into(),
            },
            BlockDevice::new(
                core,
                BaseImage::new(vec![0x5a; 32]),
                BlockLatency::default(),
            ),
            Seed::from_u64(7),
        )
    }

    #[test]
    fn reversed_collection_preserves_real_origin_and_canonical_checkpoint_bytes() {
        let arrivals = vec![
            (0, BlockRequest::read(1, 0, 4)),
            (200_000, BlockRequest::read(2, 0, 4)),
        ];
        let mut reversed = arrivals.clone();
        reversed.reverse();
        let mut first = device();
        let mut second = device();

        first
            .submit_arrivals(arrivals)
            .unwrap_or_else(|error| panic!("first complete phase: {error}"));
        second
            .submit_arrivals(reversed)
            .unwrap_or_else(|error| panic!("reversed complete phase: {error}"));

        assert_eq!(first.checkpoint(), second.checkpoint());
        assert_eq!(
            first
                .checkpoint()
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("encode original queue: {error}")),
            second
                .checkpoint()
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("encode reversed queue: {error}"))
        );
        let deliveries = first.deliver_due(u64::MAX);
        assert_eq!(deliveries.len(), 2);
        for (sequence, delivery) in deliveries.iter().enumerate() {
            let completion = delivery
                .completion
                .as_ref()
                .unwrap_or_else(|| panic!("actual computed completion"));
            assert_eq!(completion.source_delivery.seq, sequence as u32);
            assert_eq!(completion.source_delivery.src_node, 7);
            assert_eq!(
                completion.source_delivery.delivery_icount,
                delivery.delivery_icount
            );
        }
        assert_eq!(deliveries, second.deliver_due(u64::MAX));
    }

    #[test]
    fn ambiguous_batch_refuses_before_original_queue_or_payload_mutation() {
        let mut device = device();
        let before = device.checkpoint();

        assert_eq!(
            device.submit_arrivals(vec![
                (0, BlockRequest::write(1, 0, vec![1])),
                (0, BlockRequest::write(1, 0, vec![2]))
            ]),
            Err(DeviceError::AmbiguousModeledArrival)
        );

        assert_eq!(device.checkpoint(), before);
    }
}
