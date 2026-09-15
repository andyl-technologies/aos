//! Live block and 9p callback adapter tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::BlockOperation;
use crate::runtime::callback_quiescence::LiveCallbackQuiescence;

use super::*;

use crate::runtime::LiveRuntimeTeardownRouter;

use crucible_shmem::{
    AcceleratorEntry, DirectedRing, KIND_VM, MappedDirectedRingMut, RegionConfig, RegionHeader,
    RegionLayout, SLOT_9P_IO, SLOT_BLK_IO, authorize_advance_ceiling,
};

mod adapters;
mod callbacks;
mod idle_advance;

static FORCE_VCPU_EXIT_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn test_deadline() -> i64 {
    -1
}

extern "C" fn test_advance(_target: i64) -> c_int {
    0
}

extern "C" fn test_icount_raw() -> u64 {
    0
}

extern "C" fn capture_force_vcpu_exit() {
    FORCE_VCPU_EXIT_CALLS.fetch_add(1, Ordering::SeqCst);
}

struct DeviceRingStorage {
    block_out_header: RingHeader,
    block_out_entries: Vec<FrameEntry>,
    block_in_header: RingHeader,
    block_in_entries: Vec<FrameEntry>,
    ninep_out_header: RingHeader,
    ninep_out_entries: Vec<FrameEntry>,
    ninep_in_header: RingHeader,
    ninep_in_entries: Vec<FrameEntry>,
    accelerator_request_header: RingHeader,
    accelerator_request_entries: Vec<AcceleratorEntry>,
    accelerator_completion_header: RingHeader,
    accelerator_completion_entries: Vec<AcceleratorEntry>,
}

impl DeviceRingStorage {
    fn new() -> Self {
        Self {
            block_out_header: RingHeader::new(),
            block_out_entries: vec![FrameEntry::default(); 4],
            block_in_header: RingHeader::new(),
            block_in_entries: vec![FrameEntry::default(); 4],
            ninep_out_header: RingHeader::new(),
            ninep_out_entries: vec![FrameEntry::default(); 4],
            ninep_in_header: RingHeader::new(),
            ninep_in_entries: vec![FrameEntry::default(); 4],
            accelerator_request_header: RingHeader::new(),
            accelerator_request_entries: vec![AcceleratorEntry::default(); 4],
            accelerator_completion_header: RingHeader::new(),
            accelerator_completion_entries: vec![AcceleratorEntry::default(); 4],
        }
    }

    fn block_pair(&mut self) -> LiveDirectedRingPair {
        ring_pair(
            0,
            SLOT_BLK_IO as u32,
            2,
            3,
            &self.block_out_header,
            &mut self.block_out_entries,
            &self.block_in_header,
            &mut self.block_in_entries,
        )
    }

    fn ninep_pair(&mut self) -> LiveDirectedRingPair {
        ring_pair(
            0,
            SLOT_9P_IO as u32,
            4,
            5,
            &self.ninep_out_header,
            &mut self.ninep_out_entries,
            &self.ninep_in_header,
            &mut self.ninep_in_entries,
        )
    }

    fn accelerator_rings(&mut self) -> DetachedPluginAcceleratorRings {
        // SAFETY: this fixture retains the four allocations for the complete
        // handle lifetime and creates only one plugin role per test.
        unsafe {
            DetachedPluginAcceleratorRings::from_raw_parts(
                &self.accelerator_request_header,
                self.accelerator_request_entries.as_mut_ptr(),
                self.accelerator_request_entries.len(),
                &self.accelerator_completion_header,
                self.accelerator_completion_entries.as_mut_ptr(),
                self.accelerator_completion_entries.len(),
            )
        }
        .unwrap_or_else(|| panic!("accelerator test rings should be nonempty"))
    }
}

// crucible-lint: allow rust-allow -- the fixture spells both directed endpoints and their distinct backing stores.
#[allow(
    clippy::too_many_arguments,
    reason = "the test helper spells both directed ring endpoints and backing stores"
)]
fn ring_pair(
    vm_slot: u32,
    executor_slot: u32,
    outbound_index: u32,
    inbound_index: u32,
    outbound_header: &RingHeader,
    outbound_entries: &mut [FrameEntry],
    inbound_header: &RingHeader,
    inbound_entries: &mut [FrameEntry],
) -> LiveDirectedRingPair {
    LiveDirectedRingPair::new(
        MappedDirectedRingMut {
            descriptor: DirectedRing {
                index: outbound_index,
                src_slot: vm_slot,
                dst_slot: executor_slot,
            },
            header: outbound_header,
            entries: outbound_entries,
        },
        MappedDirectedRingMut {
            descriptor: DirectedRing {
                index: inbound_index,
                src_slot: executor_slot,
                dst_slot: vm_slot,
            },
            header: inbound_header,
            entries: inbound_entries,
        },
    )
    .unwrap_or_else(|error| panic!("test ring handles should build: {error}"))
}

fn enqueue_response(
    header: &RingHeader,
    entries: &mut [FrameEntry],
    delivery_icount: u64,
    source: u32,
    sequence: u32,
    payload: &[u8],
) {
    let frame = FrameEntry::new(delivery_icount, source, sequence, payload)
        .unwrap_or_else(|error| panic!("test response frame should build: {error}"));
    header
        .enqueue(entries, &frame)
        .unwrap_or_else(|error| panic!("test response should enqueue: {error}"));
}
