//! Atomic scheduler input, ceiling, and wake publication.

use super::*;

impl RegionAllocation {
    /// Publishes pending inputs, then the scheduler ceiling, then the futex wake.
    ///
    /// This is the scheduler-side handoff primitive for RUN publication. Every
    /// pending frame is release-published to its directed inbox before the node
    /// slot release-stores `max_advance_icount` and increments `wake_signal`, so
    /// a woken plugin can acquire-observe a consistent `(ceiling,
    /// pending-inputs)` snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerWakePublicationError`] when the consumer slot does not
    /// exist, an inbox ring is missing or full, or the node slot rejects the
    /// scheduler ceiling or futex wake.
    pub fn publish_scheduler_inputs_and_ceiling(
        &mut self,
        dst_slot: u32,
        pending_inputs: &[PendingInputPublication],
        ceiling: AdvanceCeiling,
    ) -> Result<SchedulerWakePublication, SchedulerWakePublicationError> {
        let dst_index = self.slot_index(dst_slot)?;
        self.slots[dst_index].validate_scheduler_ceiling(ceiling)?;
        let enqueue_plans = self.scheduler_wake_enqueue_plans(dst_slot, pending_inputs)?;
        self.preflight_scheduler_wake_capacity(&enqueue_plans)?;

        for plan in enqueue_plans {
            let frame = &pending_inputs[plan.input_index].frame;
            self.ring_headers[plan.ring_index]
                .enqueue(&mut self.frame_entries[plan.entry_range], frame)
                .map_err(RegionAllocationAccessError::from)?;
        }

        let wake = self.slots[dst_index].publish_prevalidated_scheduler_ceiling(ceiling)?;
        Ok(SchedulerWakePublication {
            dst_slot,
            pending_input_count: pending_inputs.len(),
            max_advance_icount: ceiling.max_advance_icount,
            wake,
        })
    }

    /// Returns the head frame of a directed ring without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the directed ring does not
    /// exist, the backing range cannot be represented locally, or the SPSC peek
    /// operation rejects the ring state.
    pub fn peek_directed_frame(
        &self,
        src_slot: u32,
        dst_slot: u32,
    ) -> Result<Option<FrameEntry>, RegionAllocationAccessError> {
        let ring_index = self.ring_index(src_slot, dst_slot)?;
        let entry_range = self.entry_range(ring_index)?;
        Ok(self.ring_headers[ring_index].peek(&self.frame_entries[entry_range])?)
    }

    /// Returns the head frame's delivery icount without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the directed ring does not
    /// exist, the backing range cannot be represented locally, or the SPSC peek
    /// operation rejects the ring state.
    pub fn peek_directed_delivery_icount(
        &self,
        src_slot: u32,
        dst_slot: u32,
    ) -> Result<Option<u64>, RegionAllocationAccessError> {
        let ring_index = self.ring_index(src_slot, dst_slot)?;
        let entry_range = self.entry_range(ring_index)?;
        Ok(self.ring_headers[ring_index].peek_delivery_icount(&self.frame_entries[entry_range])?)
    }

    /// Dequeues the head frame from a directed ring.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the directed ring does not
    /// exist, the backing range cannot be represented locally, or the SPSC
    /// dequeue operation rejects the ring state.
    pub fn dequeue_directed_frame(
        &self,
        src_slot: u32,
        dst_slot: u32,
    ) -> Result<Option<FrameEntry>, RegionAllocationAccessError> {
        let ring_index = self.ring_index(src_slot, dst_slot)?;
        let entry_range = self.entry_range(ring_index)?;
        Ok(self.ring_headers[ring_index].dequeue(&self.frame_entries[entry_range])?)
    }

    fn slot_index(&self, slot: u32) -> Result<usize, SchedulerWakePublicationError> {
        let index = usize::try_from(slot)
            .map_err(|_error| SchedulerWakePublicationError::UnknownNodeSlot { slot })?;
        if index >= self.slots.len() {
            Err(SchedulerWakePublicationError::UnknownNodeSlot { slot })
        } else {
            Ok(index)
        }
    }

    fn scheduler_wake_enqueue_plans(
        &self,
        dst_slot: u32,
        pending_inputs: &[PendingInputPublication],
    ) -> Result<Vec<SchedulerWakeEnqueuePlan>, SchedulerWakePublicationError> {
        let mut plans = Vec::with_capacity(pending_inputs.len());
        for (input_index, input) in pending_inputs.iter().enumerate() {
            validate_pending_input_source(input_index, input.src_slot, &input.frame)?;
            let ring_index = self.ring_index(input.src_slot, dst_slot)?;
            let entry_range = self.entry_range(ring_index)?;
            plans.push(SchedulerWakeEnqueuePlan {
                ring_index,
                entry_range,
                input_index,
            });
        }
        Ok(plans)
    }

    fn preflight_scheduler_wake_capacity(
        &self,
        plans: &[SchedulerWakeEnqueuePlan],
    ) -> Result<(), RegionAllocationAccessError> {
        let mut checked_rings = Vec::new();
        for plan in plans {
            if checked_rings.contains(&plan.ring_index) {
                continue;
            }
            checked_rings.push(plan.ring_index);
            let ring = &self.ring_headers[plan.ring_index];
            let batch_count = plans
                .iter()
                .filter(|candidate| candidate.ring_index == plan.ring_index)
                .count() as u64;
            let entries = self.entry_range(plan.ring_index)?;
            preflight_ring_enqueue_capacity(ring, &self.frame_entries[entries], batch_count)?;
        }
        Ok(())
    }

    fn ring_index(
        &self,
        src_slot: u32,
        dst_slot: u32,
    ) -> Result<usize, RegionAllocationAccessError> {
        let ring = self
            .rings
            .iter()
            .find(|ring| ring.src_slot == src_slot && ring.dst_slot == dst_slot)
            .ok_or(RegionAllocationAccessError::UnknownDirectedRing { src_slot, dst_slot })?;
        usize::try_from(ring.index).map_err(|_error| {
            RegionAllocationAccessError::RingIndexOutOfRange {
                ring_index: ring.index,
            }
        })
    }

    fn entry_range(
        &self,
        ring_index: usize,
    ) -> Result<std::ops::Range<usize>, RegionAllocationAccessError> {
        let reported_ring_index = u32::try_from(ring_index).unwrap_or(u32::MAX);
        let capacity = usize::try_from(self.layout.queue_capacity).map_err(|_error| {
            RegionAllocationAccessError::RingEntryRangeOverflow {
                ring_index: reported_ring_index,
            }
        })?;
        let start = ring_index.checked_mul(capacity).ok_or(
            RegionAllocationAccessError::RingEntryRangeOverflow {
                ring_index: reported_ring_index,
            },
        )?;
        let end = start.checked_add(capacity).ok_or(
            RegionAllocationAccessError::RingEntryRangeOverflow {
                ring_index: reported_ring_index,
            },
        )?;
        if end > self.frame_entries.len() {
            return Err(RegionAllocationAccessError::RingEntryRangeOverflow {
                ring_index: reported_ring_index,
            });
        }
        Ok(start..end)
    }

    fn guest_introspection_entry_range(
        &self,
        vm_slot: u32,
        direction: GuestIntrospectionRingDirection,
    ) -> Result<(usize, std::ops::Range<usize>), RegionAllocationAccessError> {
        if vm_slot >= self.layout.vm_node_count {
            return Err(RegionAllocationAccessError::UnknownGuestIntrospectionRing {
                vm_slot,
                vm_node_count: self.layout.vm_node_count,
            });
        }
        let wire_index = direction.ring_index(vm_slot).ok_or(
            RegionAllocationAccessError::GuestIntrospectionEntryRangeOverflow {
                ring_index: u32::MAX,
            },
        )?;
        let ring_index = usize::try_from(wire_index).map_err(|_error| {
            RegionAllocationAccessError::GuestIntrospectionEntryRangeOverflow {
                ring_index: wire_index,
            }
        })?;
        let capacity =
            usize::try_from(self.layout.guest_introspection_queue_capacity).map_err(|_error| {
                RegionAllocationAccessError::GuestIntrospectionEntryRangeOverflow {
                    ring_index: wire_index,
                }
            })?;
        let start = ring_index.checked_mul(capacity).ok_or(
            RegionAllocationAccessError::GuestIntrospectionEntryRangeOverflow {
                ring_index: wire_index,
            },
        )?;
        let end = start.checked_add(capacity).ok_or(
            RegionAllocationAccessError::GuestIntrospectionEntryRangeOverflow {
                ring_index: wire_index,
            },
        )?;
        if end > self.guest_introspection_entries.len() {
            return Err(
                RegionAllocationAccessError::GuestIntrospectionEntryRangeOverflow {
                    ring_index: wire_index,
                },
            );
        }
        Ok((ring_index, start..end))
    }
}
