//! Golden-vector primitive codecs and typed fixture records.

pub(super) fn read_u8(bytes: &[u8], offset: usize) -> u8 {
    bytes[offset]
}

pub(super) fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let mut out = [0; 2];
    out.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(out)
}

pub(super) fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut out = [0; 4];
    out.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(out)
}

pub(super) fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut out = [0; 8];
    out.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(out)
}

pub(super) fn write_u8(bytes: &mut [u8], offset: usize, value: u8) {
    bytes[offset] = value;
}

pub(super) fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Fixture {
    pub(super) abi_version: u32,
    pub(super) bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GoldenState {
    pub(super) region: RegionHeaderState,
    pub(super) node: NodeSlotState,
    pub(super) ring: RingHeaderState,
    pub(super) frame: FrameEntryState,
    pub(super) coverage: CoverageEntryState,
    pub(super) whitebox_marker: WhiteboxMarkerEntryState,
    pub(super) guest_introspection: GuestIntrospectionEntryState,
    pub(super) accelerator: AcceleratorEntryState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RegionHeaderState {
    pub(super) magic: u64,
    pub(super) abi_version: u32,
    pub(super) node_count: u32,
    pub(super) queue_capacity: u32,
    pub(super) ring_count: u32,
    pub(super) ring_hdr_off: u64,
    pub(super) ring_data_off: u64,
    pub(super) entry_stride: u64,
    pub(super) region_size: u64,
    pub(super) icount_shift: u32,
    pub(super) pause_requested: u8,
    pub(super) shutdown_requested: u8,
    pub(super) fault_payload_arena_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NodeSlotState {
    pub(super) current_icount: u64,
    pub(super) current_ns: u64,
    pub(super) max_advance_icount: u64,
    pub(super) idle_wake_icount: u64,
    pub(super) wake_signal: u32,
    pub(super) status: u8,
    pub(super) kind: u8,
    pub(super) device_io_active: u8,
    pub(super) publish_gen: u32,
    pub(super) control_boundary_ack: u32,
    pub(super) preemption_at_icount: u64,
    pub(super) preemption_deadline_icount: u64,
    pub(super) preemption_ceiling_icount: u64,
    pub(super) preemption_published_sequence: u32,
    pub(super) preemption_consumed_sequence: u32,
    pub(super) preemption_arg0: u32,
    pub(super) preemption_arg1: u32,
    pub(super) preemption_kind: u8,
    pub(super) logical_time_raw_icount: u64,
    pub(super) logical_time_restore_target: u64,
    pub(super) logical_time_restore_request: u32,
    pub(super) logical_time_restore_ack: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RingHeaderState {
    pub(super) read_idx: u64,
    pub(super) write_idx: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrameEntryState {
    pub(super) delivery_icount: u64,
    pub(super) src_node: u32,
    pub(super) seq: u32,
    pub(super) payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CoverageEntryState {
    pub(super) current_icount: u64,
    pub(super) guest_pc: u64,
    pub(super) map_index: u64,
    pub(super) vcpu_index: u32,
    pub(super) block_len: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WhiteboxMarkerEntryState {
    pub(super) current_icount: u64,
    pub(super) vcpu_index: u32,
    pub(super) kind: u16,
    pub(super) payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GuestIntrospectionEntryState {
    pub(super) sequence: u64,
    pub(super) record: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AcceleratorEntryState {
    pub(super) sequence: u64,
    pub(super) generation: u64,
    pub(super) device_id: Vec<u8>,
    pub(super) class: u16,
    pub(super) job_kind: u16,
    pub(super) queue_id: u16,
    pub(super) service_units: u64,
    pub(super) data: Vec<u8>,
}
