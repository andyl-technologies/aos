//! Block request admission, reset, service, and delivery lifecycle.

use super::*;

impl BlockDevice {
    /// Enqueues an encoded request and COMPUTEs it immediately.
    ///
    /// This is the ARRIVE+COMPUTE convenience path for the in-process double
    /// ([IO-27]): the wire bytes of `request` are wrapped into the uniform
    /// [`Request`] at `request_icount`, enqueued, and COMPUTEd, fixing the
    /// response's `delivery_icount`. The response stays in flight until
    /// [`BlockDevice::advance_to`] reaches that icount.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Codec`] when `request` cannot be encoded (a write
    /// payload exceeding the `u32` wire `count` field), [`DeviceError::RingFull`]
    /// when the inbound ring is full (the producer must drain and retry,
    /// [IO-32]), or any error [`IoCore::process_inbox`] raises
    /// (clock/overflow/past-delivery guards).
    pub fn submit(
        &mut self,
        request_icount: u64,
        request: &BlockRequest,
    ) -> Result<(), DeviceError> {
        let mut next_faults = self.storage_faults.clone();
        if let Some(response) =
            next_faults.dispose_retired_transport_request_if_needed(request.identity())?
        {
            let mut next_core = self.core.clone();
            next_core.schedule_response_now(response)?;
            self.storage_faults = next_faults;
            self.core = next_core;
            return Ok(());
        }
        self.advance_storage_service_before_admission(request_icount)?;
        let wire = request.encode().map_err(DeviceError::Codec)?;
        let uniform = Request::new(request_icount, request.request_id, wire);
        self.core
            .enqueue_request(uniform)
            .map_err(|rejected| DeviceError::RingFull {
                capacity: rejected.capacity,
            })?;
        // Borrow split: process_inbox needs `&mut self.core` and `&mut device`
        // simultaneously, so serve through a detached server view.
        Self::process_pending(
            &mut self.core,
            &self.base,
            &mut self.overlay,
            &mut self.storage_faults,
            &self.latency,
        )
    }

    /// Drains raw block request frames from a shared-memory inbox ring.
    ///
    /// Each dequeued frame is converted to the uniform [`Request`] payload,
    /// COMPUTEd through the block server, and inserted into the in-flight queue.
    /// The VM producer slot is woken as each request-ring entry is freed, so a
    /// producer blocked on a full `(vm slot -> SLOT_BLK_IO)` ring can retry
    /// without dropping or reordering the request ([IO-32]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for corrupt ring state, invalid frame payload
    /// length, wake failure, or any block COMPUTE/delivery-time error.
    pub fn process_shmem_inbox(
        &mut self,
        inbox: &RingHeader,
        inbox_entries: &[FrameEntry],
        producer_slot: &NodeSlot,
    ) -> Result<ShmemInboxProcess, DeviceError> {
        let mut result = ShmemInboxProcess {
            processed: 0,
            request_kinds: Vec::new(),
            first_request_icount: None,
            producer_wakes: Vec::new(),
        };
        loop {
            let one = self.process_one_shmem_request(inbox, inbox_entries, producer_slot)?;
            if one.processed == 0 {
                break;
            }
            result.processed += one.processed;
            result.request_kinds.extend(one.request_kinds);
            if result.first_request_icount.is_none() {
                result.first_request_icount = one.first_request_icount;
            }
            result.producer_wakes.extend(one.producer_wakes);
        }
        Ok(result)
    }

    /// Drains and COMPUTEs at most one raw shared-memory block request.
    ///
    /// This is the worker-dispatch counterpart to
    /// [`BlockDevice::process_shmem_inbox`]: callers can pin the head request's
    /// completion coordinate before dispatch, then consume precisely that
    /// request on the worker.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`BlockDevice::process_shmem_inbox`].
    pub fn process_one_shmem_request(
        &mut self,
        inbox: &RingHeader,
        inbox_entries: &[FrameEntry],
        producer_slot: &NodeSlot,
    ) -> Result<ShmemInboxProcess, DeviceError> {
        if let Some(frame) = inbox.peek(inbox_entries)? {
            let payload = frame.payload()?;
            let request_kind = payload.first().copied();
            let request = BlockRequest::decode(payload).map_err(DeviceError::Codec)?;
            let mut next_faults = self.storage_faults.clone();
            if let Some(response) =
                next_faults.dispose_retired_transport_request_if_needed(request.identity())?
            {
                let mut next_core = self.core.clone();
                next_core.schedule_response_now(response)?;
                let committed = inbox
                    .dequeue(inbox_entries)?
                    .ok_or(DeviceError::InvalidComputedResponse)?;
                if committed != frame {
                    return Err(DeviceError::InvalidComputedResponse);
                }
                let wake = producer_slot.wake_for_device_io_release()?;
                self.storage_faults = next_faults;
                self.core = next_core;
                return Ok(ShmemInboxProcess {
                    processed: 1,
                    request_kinds: vec![request_kind],
                    first_request_icount: Some(frame.delivery_icount),
                    producer_wakes: vec![wake],
                });
            }
            self.advance_storage_service_before_admission(frame.delivery_icount)?;
        }
        let mut node = BlockServer {
            base: &self.base,
            overlay: &mut self.overlay,
            storage_faults: &mut self.storage_faults,
            latency: &self.latency,
        };
        self.core
            .process_one_shmem_request(&mut node, inbox, inbox_entries, producer_slot)
    }

    pub(super) fn advance_storage_service_before_admission(
        &mut self,
        request_icount: u64,
    ) -> Result<(), DeviceError> {
        let now_nanos = icount_to_virtual_ns(request_icount, self.core.shift_bits())?;
        self.reject_advance_past_unresolved_execution(now_nanos)?;
        let mut next_faults = self.storage_faults.clone();
        let mut next_overlay = self.overlay.clone();
        let mut next_core = self.core.clone();
        let mut released =
            next_faults.advance_service_to(&self.base, &mut next_overlay, now_nanos)?;
        released.extend(next_faults.resume_execution_to(
            &self.base,
            &mut next_overlay,
            now_nanos,
        )?);
        released.extend(next_faults.resume_request_persistence_to(
            &self.base,
            &mut next_overlay,
            now_nanos,
        )?);
        released.extend(next_faults.resume_delivery_to(now_nanos)?);
        for released in released {
            let latency_nanos = self
                .latency
                .latency_for(released.request.op, released.request.count);
            let base_completion_nanos = released.finished_nanos.checked_add(latency_nanos).ok_or(
                DeviceError::CompletionOverflow {
                    request_icount: released.request_icount,
                    latency_ns: latency_nanos,
                },
            )?;
            next_core
                .schedule_computed_response_at_nanos(base_completion_nanos, released.computed)?;
        }
        self.storage_faults = next_faults;
        self.overlay = next_overlay;
        self.core = next_core;
        Ok(())
    }

    pub(super) fn prepare_transport_reset(
        core: &IoCore,
        storage_faults: &BlockFaultState,
        event: &crate::inflight::PendingResponse,
        reset: BlockTransportReset,
        delivered_icount: u64,
    ) -> Result<PreparedBlockTransportReset, DeviceError> {
        let mut next_faults = storage_faults.clone();
        let delivered_nanos = icount_to_virtual_ns(delivered_icount, core.shift_bits())?;
        let emulator_virtual_limit = i64::MAX as u64;
        if delivered_nanos > emulator_virtual_limit
            || reset.recovery_nanos > emulator_virtual_limit
            || delivered_nanos
                .checked_add(reset.recovery_nanos)
                .is_none_or(|deadline| deadline > emulator_virtual_limit)
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "block transport recovery exceeds QEMU virtual-clock range",
            });
        }
        let immediate = next_faults.apply_transport_reset(reset, delivered_nanos)?;
        core.check_response_sequence_capacity(immediate.len())?;

        let mut inflight = Vec::with_capacity(core.inflight_len().saturating_sub(1));
        for mut pending in core.take_inflight_from_snapshot() {
            if pending.key == event.key {
                continue;
            }
            if pending.key > event.key {
                let response =
                    BlockResponse::decode(&pending.response.payload).map_err(DeviceError::Codec)?;
                if matches!(response.status, BlockStatus::Ok | BlockStatus::Error)
                    && reset.completed_undelivered != BlockTransportUndelivered::Complete
                {
                    let replacement = match reset.completed_undelivered {
                        BlockTransportUndelivered::Complete => response,
                        BlockTransportUndelivered::Fail => {
                            BlockResponse::error_for(response.identity(), reset.failure_result)
                        }
                        BlockTransportUndelivered::RetryPreserveId => {
                            BlockResponse::reset_disposition(
                                response.identity(),
                                BlockStatus::RetryPreserveId,
                            )
                        }
                        BlockTransportUndelivered::RetryNewId => BlockResponse::reset_disposition(
                            response.identity(),
                            BlockStatus::RetryNewId,
                        ),
                        BlockTransportUndelivered::DropCompletion => {
                            BlockResponse::reset_disposition(
                                response.identity(),
                                BlockStatus::DropCompletion,
                            )
                        }
                    };
                    pending.response = block_response_to_uniform_device(&replacement)?;
                }
            }
            inflight.push(pending);
        }
        Ok(PreparedBlockTransportReset {
            storage_faults: next_faults,
            inflight,
            immediate,
        })
    }

    pub(super) fn commit_transport_reset(
        core: &mut IoCore,
        storage_faults: &mut BlockFaultState,
        prepared: PreparedBlockTransportReset,
    ) -> Result<(), DeviceError> {
        let _discarded = core.take_inflight();
        core.replace_inflight(prepared.inflight);
        *storage_faults = prepared.storage_faults;
        for response in prepared.immediate {
            core.schedule_response_now(response)?;
        }
        Ok(())
    }

    pub(super) fn deliver_local_with_resets(
        core: &mut IoCore,
        storage_faults: &mut BlockFaultState,
        limit: u64,
    ) -> Result<usize, DeviceError> {
        let mut delivered = 0;
        while let Some(head) = core.next_pending_response().cloned() {
            if head.delivery_icount() > limit {
                break;
            }
            let publish_at = head.delivery_icount().max(core.current_icount());
            let decoded =
                BlockResponse::decode(&head.response.payload).map_err(DeviceError::Codec)?;
            let prepared = if decoded.status == BlockStatus::TransportReset {
                let reset = decoded
                    .transport_reset_directive()
                    .map_err(DeviceError::Codec)?;
                Some(Self::prepare_transport_reset(
                    core,
                    storage_faults,
                    &head,
                    reset,
                    publish_at,
                )?)
            } else {
                None
            };
            if core.deliver_one(publish_at)?.is_none() {
                break;
            }
            delivered += 1;
            if let Some(prepared) = prepared {
                Self::commit_transport_reset(core, storage_faults, prepared)?;
            }
        }
        if core.current_icount() < limit {
            let _ = core.deliver_one(limit)?;
        }
        Ok(delivered)
    }

    pub(super) fn deliver_shmem_with_resets(
        core: &mut IoCore,
        storage_faults: &mut BlockFaultState,
        limit: u64,
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
        consumer_slot: &NodeSlot,
    ) -> Result<ShmemDeliveryResult, DeviceError> {
        let mut delivered = 0;
        let mut consumer_wake = None;
        while let Some(head) = core.next_pending_response().cloned() {
            if head.delivery_icount() > limit {
                break;
            }
            let publish_at = head.delivery_icount().max(core.current_icount());
            let decoded =
                BlockResponse::decode(&head.response.payload).map_err(DeviceError::Codec)?;
            let prepared = if decoded.status == BlockStatus::TransportReset {
                let reset = decoded
                    .transport_reset_directive()
                    .map_err(DeviceError::Codec)?;
                Some(Self::prepare_transport_reset(
                    core,
                    storage_faults,
                    &head,
                    reset,
                    publish_at,
                )?)
            } else {
                None
            };
            let published =
                core.deliver_one_shmem(publish_at, outbox, outbox_entries, consumer_slot);
            let Some(_published) = (match published {
                Ok(published) => published,
                Err(error) => {
                    if delivered != 0 {
                        let _ = consumer_slot.wake_for_frame_delivery()?;
                    }
                    return Err(error);
                }
            }) else {
                break;
            };
            delivered += 1;
            if let Some(prepared) = prepared {
                Self::commit_transport_reset(core, storage_faults, prepared)?;
            }
        }
        if core.current_icount() < limit {
            let published = core.deliver_one_shmem(limit, outbox, outbox_entries, consumer_slot)?;
            if let Some(_response) = published {
                delivered += 1;
            }
        }
        if delivered != 0 {
            consumer_wake = Some(consumer_slot.wake_for_frame_delivery()?);
        }
        Ok(ShmemDeliveryResult {
            delivered,
            consumer_wake,
        })
    }

    /// Advances the clock to `limit` and DELIVERs every due response ([IO-2]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ClockRegression`] when `limit` is below the current
    /// icount.
    pub fn advance_to(&mut self, limit: u64) -> Result<usize, DeviceError> {
        let now_nanos = icount_to_virtual_ns(limit, self.core.shift_bits())?;
        self.reject_advance_past_unresolved_execution(now_nanos)?;
        let mut next_faults = self.storage_faults.clone();
        let mut next_overlay = self.overlay.clone();
        let mut next_core = self.core.clone();
        let mut released =
            next_faults.advance_service_to(&self.base, &mut next_overlay, now_nanos)?;
        released.extend(next_faults.resume_execution_to(
            &self.base,
            &mut next_overlay,
            now_nanos,
        )?);
        released.extend(next_faults.resume_request_persistence_to(
            &self.base,
            &mut next_overlay,
            now_nanos,
        )?);
        released.extend(next_faults.resume_delivery_to(now_nanos)?);
        for released in released {
            let base_completion_nanos = released
                .finished_nanos
                .checked_add(
                    self.latency
                        .latency_for(released.request.op, released.request.count),
                )
                .ok_or(DeviceError::CompletionOverflow {
                    request_icount: released.request_icount,
                    latency_ns: self
                        .latency
                        .latency_for(released.request.op, released.request.count),
                })?;
            next_core
                .schedule_computed_response_at_nanos(base_completion_nanos, released.computed)?;
        }
        let delivered = Self::deliver_local_with_resets(&mut next_core, &mut next_faults, limit)?;
        self.storage_faults = next_faults;
        self.overlay = next_overlay;
        self.core = next_core;
        Ok(delivered)
    }

    /// Advances the clock and publishes due block responses to a shmem ring.
    ///
    /// Responses are emitted as raw `BlockResponse` payload frames on the
    /// `(SLOT_BLK_IO -> vm slot)` ring. If the ring fills, undelivered responses
    /// remain in flight at their original `delivery_icount`; when at least one
    /// response is published, the VM consumer slot is woken.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for clock regression, oversized response frames,
    /// corrupt ring state, or wake failure.
    pub fn advance_to_shmem(
        &mut self,
        limit: u64,
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
        consumer_slot: &NodeSlot,
    ) -> Result<ShmemDeliveryResult, DeviceError> {
        let now_nanos = icount_to_virtual_ns(limit, self.core.shift_bits())?;
        self.reject_advance_past_unresolved_execution(now_nanos)?;
        let mut next_faults = self.storage_faults.clone();
        let mut next_overlay = self.overlay.clone();
        let mut next_core = self.core.clone();
        let mut released =
            next_faults.advance_service_to(&self.base, &mut next_overlay, now_nanos)?;
        released.extend(next_faults.resume_execution_to(
            &self.base,
            &mut next_overlay,
            now_nanos,
        )?);
        released.extend(next_faults.resume_request_persistence_to(
            &self.base,
            &mut next_overlay,
            now_nanos,
        )?);
        released.extend(next_faults.resume_delivery_to(now_nanos)?);
        for released in released {
            let latency_nanos = self
                .latency
                .latency_for(released.request.op, released.request.count);
            let base_completion_nanos = released.finished_nanos.checked_add(latency_nanos).ok_or(
                DeviceError::CompletionOverflow {
                    request_icount: released.request_icount,
                    latency_ns: latency_nanos,
                },
            )?;
            next_core
                .schedule_computed_response_at_nanos(base_completion_nanos, released.computed)?;
        }
        self.storage_faults = next_faults;
        self.overlay = next_overlay;
        self.core = next_core;
        Self::deliver_shmem_with_resets(
            &mut self.core,
            &mut self.storage_faults,
            limit,
            outbox,
            outbox_entries,
            consumer_slot,
        )
    }

    pub(super) fn reject_advance_past_unresolved_execution(
        &self,
        requested_nanos: u64,
    ) -> Result<(), DeviceError> {
        if let Some(ready_nanos) = self.storage_faults.next_execution_deadline_nanos()
            && ready_nanos < requested_nanos
        {
            return Err(DeviceError::UnresolvedBlockFaultOpportunity {
                ready_nanos,
                requested_nanos,
            });
        }
        if let Some(ready_nanos) = self
            .storage_faults
            .next_request_persistence_deadline_nanos()
            && ready_nanos < requested_nanos
        {
            return Err(DeviceError::UnresolvedBlockFaultOpportunity {
                ready_nanos,
                requested_nanos,
            });
        }
        if let Some(ready_nanos) = self.storage_faults.next_delivery_deadline_nanos()
            && ready_nanos < requested_nanos
        {
            return Err(DeviceError::UnresolvedBlockFaultOpportunity {
                ready_nanos,
                requested_nanos,
            });
        }
        Ok(())
    }

    /// Pops the next delivered response, decoding it from wire bytes.
    ///
    /// Returns `None` when no response has been made visible yet. The returned
    /// value is the decoded [`BlockResponse`]. A decode failure is surfaced as
    /// an error rather than silently dropped.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Codec`] when a delivered response payload fails to
    /// decode. For responses this device itself produced this cannot occur; it
    /// can surface only if the outbound ring was restored from an untrusted
    /// snapshot whose bytes were not produced by this codec.
    pub fn next_response(&mut self) -> Result<Option<BlockResponse>, DeviceError> {
        match self.core.pop_response() {
            Some(pending) => {
                let decoded =
                    BlockResponse::decode(&pending.response.payload).map_err(DeviceError::Codec)?;
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }

    /// COMPUTEs every pending inbox request through the block server view.
    ///
    /// Factored out so [`BlockDevice::submit`] can satisfy the borrow checker:
    /// `IoCore::process_inbox` takes the core mutably and an [`IoSubNode`]
    /// mutably, and the device cannot hand `&mut self` to both. The detached
    /// [`BlockServer`] borrows only the device sub-fields the COMPUTE step needs.
    ///
    /// # Errors
    ///
    /// Propagates any [`DeviceError`] from [`IoCore::process_inbox`].
    pub(super) fn process_pending(
        core: &mut IoCore,
        base: &BaseImage,
        overlay: &mut CowOverlay,
        storage_faults: &mut BlockFaultState,
        latency: &BlockLatency,
    ) -> Result<(), DeviceError> {
        let mut server = BlockServer {
            base,
            overlay,
            storage_faults,
            latency,
        };
        core.process_inbox(&mut server)
    }
}
