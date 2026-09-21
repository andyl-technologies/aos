//! In-process shared-memory allocation and delivery authorization.

use super::*;

pub(super) fn sim_scheduler_node_for_slot(slot: u32) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: format!("slot-{slot}"),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

#[derive(Clone)]
pub(super) struct SimDoubleShmem {
    allocation: RegionAllocation,
}

impl SimDoubleShmem {
    pub(super) fn new(config: RegionConfig) -> Result<Self, RegionLayoutError> {
        Ok(Self {
            allocation: RegionAllocation::new_model(config)?,
        })
    }

    pub(super) fn layout(&self) -> RegionLayout {
        self.allocation.layout()
    }

    pub(super) fn header_snapshot(&self) -> RegionHeaderSnapshot {
        self.allocation.header().snapshot()
    }

    pub(super) fn node_slot(
        &self,
        slot_index: u32,
    ) -> Result<&crucible_shmem::NodeSlot, SimDoubleError> {
        self.allocation
            .node_slot(slot_index)
            .ok_or(SimDoubleError::SlotOutOfRange {
                slot_index,
                vm_node_count: self.layout().vm_node_count,
            })
    }

    pub(super) fn slot(&self, slot_index: u32) -> crucible_shmem::NodeSlotSnapshot {
        self.allocation
            .node_slot(slot_index)
            .map(crucible_shmem::NodeSlot::snapshot)
            .unwrap_or_else(|| crucible_shmem::NodeSlot::default().snapshot())
    }

    pub(super) fn inbound_sources(&self, dst_slot: u32) -> Vec<u32> {
        self.allocation
            .rings()
            .iter()
            .filter(|ring| ring.dst_slot == dst_slot)
            .map(|ring| ring.src_slot)
            .collect()
    }

    pub(super) fn enqueue_directed_frame(
        &mut self,
        src_slot: u32,
        dst_slot: u32,
        frame: &FrameEntry,
    ) -> Result<(), SimDoubleError> {
        Ok(self
            .allocation
            .enqueue_directed_frame(src_slot, dst_slot, frame)?)
    }

    pub(super) fn peek_directed_frame(
        &self,
        src_slot: u32,
        dst_slot: u32,
    ) -> Result<Option<FrameEntry>, SimDoubleError> {
        Ok(self.allocation.peek_directed_frame(src_slot, dst_slot)?)
    }

    pub(super) fn dequeue_directed_frame(
        &self,
        src_slot: u32,
        dst_slot: u32,
    ) -> Result<Option<FrameEntry>, SimDoubleError> {
        Ok(self.allocation.dequeue_directed_frame(src_slot, dst_slot)?)
    }

    pub(super) fn earliest_inbound_delivery_key(
        &self,
        dst_slot: u32,
    ) -> Result<Option<FrameDeliveryKey>, SimDoubleError> {
        let mut earliest = None;
        for src_slot in self.inbound_sources(dst_slot) {
            let Some(frame) = self.peek_directed_frame(src_slot, dst_slot)? else {
                continue;
            };
            let key = frame.delivery_key();
            if earliest
                .map(|current: FrameDeliveryKey| key < current)
                .unwrap_or(true)
            {
                earliest = Some(key);
            }
        }
        Ok(earliest)
    }
}

pub(super) fn authorize_sim_double_delivery_ceiling(
    current_icount: u64,
    max_advance_icount: u64,
    earliest_possible_delivery_icount: Option<u64>,
) -> Result<AdvanceCeiling, crucible_shmem::LookaheadGateError> {
    if earliest_possible_delivery_icount == Some(max_advance_icount) {
        authorize_advance_ceiling(current_icount, max_advance_icount, None)
    } else {
        authorize_advance_ceiling(
            current_icount,
            max_advance_icount,
            earliest_possible_delivery_icount,
        )
    }
}
