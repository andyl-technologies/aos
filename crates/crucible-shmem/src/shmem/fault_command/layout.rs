//! Fault transport constants, slots, and payload-arena layout.

use super::*;

/// Fault command ABI major version.
pub const FAULT_COMMAND_ABI_MAJOR: u16 = 1;
/// Fault command ABI minor version.
pub const FAULT_COMMAND_ABI_MINOR: u16 = 2;
/// Exact semantic version implemented by every initial command kind.
pub const FAULT_COMMAND_SEMANTIC_VERSION: u32 = 1;
/// Default maximum encoded command or result payload bytes.
///
/// This is the exact envelope for 64 replacement actions whose cumulative
/// selected bytes reach the default 1 MiB ceiling: two bytes of mask/value
/// data per selected byte, every action header and record, and the batch
/// header.
pub const DEFAULT_FAULT_PAYLOAD_BYTES: u32 = 2_106_448;
/// Hard maximum command or result payload bytes.
///
/// This admits 64 replacement actions whose cumulative selected bytes reach
/// the 16 MiB hard ceiling, including every action header and record plus the
/// batch header.
pub const HARD_FAULT_PAYLOAD_BYTES: u32 = 33_563_728;
/// Default bytes reserved for each per-node command or result payload arena.
pub const DEFAULT_FAULT_PAYLOAD_ARENA_BYTES: u32 = DEFAULT_FAULT_PAYLOAD_BYTES;
/// Hard ceiling for each per-node command or result payload arena.
pub const HARD_FAULT_PAYLOAD_ARENA_BYTES: u32 = HARD_FAULT_PAYLOAD_BYTES;
/// Default command and result ring capacity per node.
pub const DEFAULT_FAULT_COMMAND_CAPACITY: u32 = 4_096;
/// Hard command and result ring capacity per node.
pub const HARD_FAULT_COMMAND_CAPACITY: u32 = 65_536;
/// Encoded command header byte length.
pub const FAULT_COMMAND_HEADER_V1_BYTES: usize = 216;
/// Command ABI-major field offset.
pub const FAULT_COMMAND_ABI_MAJOR_OFFSET: usize = 0;
/// Command ABI-minor field offset.
pub const FAULT_COMMAND_ABI_MINOR_OFFSET: usize = 2;
/// Command-kind field offset.
pub const FAULT_COMMAND_KIND_OFFSET: usize = 4;
/// Command-flags field offset.
pub const FAULT_COMMAND_FLAGS_OFFSET: usize = 6;
/// Command safe-boundary phase field offset.
pub const FAULT_COMMAND_PHASE_OFFSET: usize = 8;
/// First command reserved field offset.
pub const FAULT_COMMAND_RESERVED0_OFFSET: usize = 10;
/// Command semantic-version field offset.
pub const FAULT_COMMAND_SEMANTIC_VERSION_OFFSET: usize = 12;
/// Command sequence field offset.
pub const FAULT_COMMAND_SEQUENCE_OFFSET: usize = 16;
/// Command target-node hash field offset.
pub const FAULT_COMMAND_TARGET_NODE_HASH_OFFSET: usize = 24;
/// Command target-icount field offset.
pub const FAULT_COMMAND_TARGET_ICOUNT_OFFSET: usize = 56;
/// Command authorization-ceiling field offset.
pub const FAULT_COMMAND_AUTHORIZATION_CEILING_OFFSET: usize = 64;
/// Command binding hash field offset.
pub const FAULT_COMMAND_BINDING_HASH_OFFSET: usize = 72;
/// Command opportunity hash field offset.
pub const FAULT_COMMAND_OPPORTUNITY_HASH_OFFSET: usize = 104;
/// Command expected-precondition hash field offset.
pub const FAULT_COMMAND_PRECONDITION_HASH_OFFSET: usize = 136;
/// Command payload hash field offset.
pub const FAULT_COMMAND_PAYLOAD_HASH_OFFSET: usize = 168;
/// Command payload-offset field offset.
pub const FAULT_COMMAND_PAYLOAD_OFFSET_OFFSET: usize = 200;
/// Command payload-length field offset.
pub const FAULT_COMMAND_PAYLOAD_LENGTH_OFFSET: usize = 208;
/// Final command reserved field offset.
pub const FAULT_COMMAND_RESERVED1_OFFSET: usize = 212;
/// Encoded result header byte length.
pub const FAULT_RESULT_HEADER_V1_BYTES: usize = 188;
/// Result ABI-major field offset.
pub const FAULT_RESULT_ABI_MAJOR_OFFSET: usize = 0;
/// Result ABI-minor field offset.
pub const FAULT_RESULT_ABI_MINOR_OFFSET: usize = 2;
/// Result command-kind field offset.
pub const FAULT_RESULT_KIND_OFFSET: usize = 4;
/// Result status field offset.
pub const FAULT_RESULT_STATUS_OFFSET: usize = 6;
/// Result semantic-version field offset.
pub const FAULT_RESULT_SEMANTIC_VERSION_OFFSET: usize = 8;
/// Result command-sequence field offset.
pub const FAULT_RESULT_SEQUENCE_OFFSET: usize = 12;
/// Result observed-icount field offset.
pub const FAULT_RESULT_OBSERVED_ICOUNT_OFFSET: usize = 20;
/// Result applied-icount field offset.
pub const FAULT_RESULT_APPLIED_ICOUNT_OFFSET: usize = 28;
/// Result capability-version field offset.
pub const FAULT_RESULT_CAPABILITY_VERSION_OFFSET: usize = 36;
/// Result safe-boundary phase field offset.
pub const FAULT_RESULT_PHASE_OFFSET: usize = 40;
/// First result reserved field offset.
pub const FAULT_RESULT_RESERVED0_OFFSET: usize = 42;
/// Result before-state hash field offset.
pub const FAULT_RESULT_BEFORE_HASH_OFFSET: usize = 44;
/// Result after-state hash field offset.
pub const FAULT_RESULT_AFTER_HASH_OFFSET: usize = 76;
/// Result evidence hash field offset.
pub const FAULT_RESULT_EVIDENCE_HASH_OFFSET: usize = 108;
/// Result payload hash field offset.
pub const FAULT_RESULT_PAYLOAD_HASH_OFFSET: usize = 140;
/// Result payload-offset field offset.
pub const FAULT_RESULT_PAYLOAD_OFFSET_OFFSET: usize = 172;
/// Result payload-length field offset.
pub const FAULT_RESULT_PAYLOAD_LENGTH_OFFSET: usize = 180;
/// Final result reserved field offset.
pub const FAULT_RESULT_RESERVED1_OFFSET: usize = 184;
/// Encoded capability row byte length.
pub const FAULT_CAPABILITY_ROW_V1_BYTES: usize = 60;
/// Capability command-kind field offset.
pub const FAULT_CAPABILITY_KIND_OFFSET: usize = 0;
/// Capability architecture/device-scope field offset.
pub const FAULT_CAPABILITY_SCOPE_OFFSET: usize = 2;
/// Capability semantic-version field offset.
pub const FAULT_CAPABILITY_SEMANTIC_VERSION_OFFSET: usize = 4;
/// Capability supported-phase mask field offset.
pub const FAULT_CAPABILITY_PHASE_MASK_OFFSET: usize = 8;
/// Capability maximum-payload field offset.
pub const FAULT_CAPABILITY_MAXIMUM_PAYLOAD_OFFSET: usize = 12;
/// Capability maximum-pending field offset.
pub const FAULT_CAPABILITY_MAXIMUM_PENDING_OFFSET: usize = 16;
/// Capability required-feature-bits field offset.
pub const FAULT_CAPABILITY_REQUIRED_FEATURES_OFFSET: usize = 20;
/// Capability identity hash field offset.
pub const FAULT_CAPABILITY_HASH_OFFSET: usize = 28;

/// Exact shared-memory size of one command transport slot.
pub const FAULT_COMMAND_SLOT_V1_BYTES: usize = 256;
/// Exact shared-memory size of one result transport slot.
pub const FAULT_RESULT_SLOT_V1_BYTES: usize = 256;
/// Exact shared-memory size of one payload-arena cursor header.
pub const FAULT_PAYLOAD_ARENA_HEADER_BYTES: usize = 128;
/// Command-slot reservation-start field offset.
pub const FAULT_COMMAND_SLOT_RESERVATION_START_OFFSET: usize =
    core::mem::offset_of!(FaultCommandSlotV1, reservation_start);
/// Command-slot payload-start field offset.
pub const FAULT_COMMAND_SLOT_PAYLOAD_START_OFFSET: usize =
    core::mem::offset_of!(FaultCommandSlotV1, payload_start);
/// Command-slot reservation-end field offset.
pub const FAULT_COMMAND_SLOT_RESERVATION_END_OFFSET: usize =
    core::mem::offset_of!(FaultCommandSlotV1, reservation_end);
/// Command-slot encoded-header field offset.
pub const FAULT_COMMAND_SLOT_HEADER_OFFSET: usize =
    core::mem::offset_of!(FaultCommandSlotV1, header);
/// Result-slot reservation-start field offset.
pub const FAULT_RESULT_SLOT_RESERVATION_START_OFFSET: usize =
    core::mem::offset_of!(FaultResultSlotV1, reservation_start);
/// Result-slot payload-start field offset.
pub const FAULT_RESULT_SLOT_PAYLOAD_START_OFFSET: usize =
    core::mem::offset_of!(FaultResultSlotV1, payload_start);
/// Result-slot reservation-end field offset.
pub const FAULT_RESULT_SLOT_RESERVATION_END_OFFSET: usize =
    core::mem::offset_of!(FaultResultSlotV1, reservation_end);
/// Result-slot encoded-header field offset.
pub const FAULT_RESULT_SLOT_HEADER_OFFSET: usize = core::mem::offset_of!(FaultResultSlotV1, header);
/// Payload-arena consumer-cursor field offset.
pub const FAULT_PAYLOAD_ARENA_READ_CURSOR_OFFSET: usize =
    core::mem::offset_of!(FaultPayloadArenaHeader, read_cursor);
/// Payload-arena producer-cursor field offset.
pub const FAULT_PAYLOAD_ARENA_WRITE_CURSOR_OFFSET: usize =
    core::mem::offset_of!(FaultPayloadArenaHeader, write_cursor);

/// One command-ring slot with transport-owned payload reservation metadata.
///
/// The reservation cursors are outside the authenticated command envelope so a
/// consumer can release arena space even when the command itself is malformed.
/// A valid command must independently agree with these bounds.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct FaultCommandSlotV1 {
    pub(super) reservation_start: u64,
    pub(super) payload_start: u64,
    pub(super) reservation_end: u64,
    pub(super) header: [u8; FAULT_COMMAND_HEADER_V1_BYTES],
    pub(super) _reserved: [u8; 16],
}

impl FaultCommandSlotV1 {
    /// Builds a zeroed, unpublished command slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reservation_start: 0,
            payload_start: 0,
            reservation_end: 0,
            header: [0; FAULT_COMMAND_HEADER_V1_BYTES],
            _reserved: [0; 16],
        }
    }

    pub(crate) fn write_bytes(&self, bytes: &mut [u8]) {
        bytes.fill(0);
        bytes[0..8].copy_from_slice(&self.reservation_start.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.payload_start.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.reservation_end.to_le_bytes());
        bytes[24..24 + FAULT_COMMAND_HEADER_V1_BYTES].copy_from_slice(&self.header);
    }
}

impl Default for FaultCommandSlotV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// One result-ring slot with transport-owned payload reservation metadata.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct FaultResultSlotV1 {
    pub(super) reservation_start: u64,
    pub(super) payload_start: u64,
    pub(super) reservation_end: u64,
    pub(super) header: [u8; FAULT_RESULT_HEADER_V1_BYTES],
    pub(super) _reserved: [u8; 44],
}

impl FaultResultSlotV1 {
    /// Builds a zeroed, unpublished result slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reservation_start: 0,
            payload_start: 0,
            reservation_end: 0,
            header: [0; FAULT_RESULT_HEADER_V1_BYTES],
            _reserved: [0; 44],
        }
    }

    pub(crate) fn write_bytes(&self, bytes: &mut [u8]) {
        bytes.fill(0);
        bytes[0..8].copy_from_slice(&self.reservation_start.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.payload_start.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.reservation_end.to_le_bytes());
        bytes[24..24 + FAULT_RESULT_HEADER_V1_BYTES].copy_from_slice(&self.header);
    }
}

impl Default for FaultResultSlotV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// SPSC byte-arena cursors shared by one payload producer and one consumer.
///
/// Cursors are monotonically increasing logical byte positions. Physical
/// offsets wrap within the fixed arena, but one payload is always contiguous;
/// the producer accounts for skipped tail bytes in the published reservation.
#[repr(C, align(128))]
pub struct FaultPayloadArenaHeader {
    pub(super) read_cursor: core::sync::atomic::AtomicU64,
    pub(super) _pad_read: [u8; 56],
    pub(super) write_cursor: core::sync::atomic::AtomicU64,
    pub(super) _pad_write: [u8; 56],
}

impl Clone for FaultPayloadArenaHeader {
    fn clone(&self) -> Self {
        Self {
            read_cursor: core::sync::atomic::AtomicU64::new(
                self.read_cursor.load(core::sync::atomic::Ordering::Acquire),
            ),
            _pad_read: [0; 56],
            write_cursor: core::sync::atomic::AtomicU64::new(
                self.write_cursor
                    .load(core::sync::atomic::Ordering::Acquire),
            ),
            _pad_write: [0; 56],
        }
    }
}

impl FaultPayloadArenaHeader {
    /// Builds an empty payload arena header.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            read_cursor: core::sync::atomic::AtomicU64::new(0),
            _pad_read: [0; 56],
            write_cursor: core::sync::atomic::AtomicU64::new(0),
            _pad_write: [0; 56],
        }
    }

    /// Returns the consumer-owned logical read cursor.
    #[must_use]
    pub fn read_cursor(&self) -> u64 {
        self.read_cursor.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Returns the producer-owned logical write cursor.
    #[must_use]
    pub fn write_cursor(&self) -> u64 {
        self.write_cursor
            .load(core::sync::atomic::Ordering::Acquire)
    }

    /// Returns whether all cache-line padding bytes remain zero.
    #[must_use]
    pub fn padding_bytes_are_zero(&self) -> bool {
        self._pad_read.iter().all(|byte| *byte == 0)
            && self._pad_write.iter().all(|byte| *byte == 0)
    }

    pub(crate) fn write_bytes(&self, bytes: &mut [u8]) {
        bytes.fill(0);
        bytes[0..8].copy_from_slice(&self.read_cursor().to_le_bytes());
        bytes[64..72].copy_from_slice(&self.write_cursor().to_le_bytes());
    }
}

impl Default for FaultPayloadArenaHeader {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<FaultCommandSlotV1>() == FAULT_COMMAND_SLOT_V1_BYTES);
const _: () = assert!(core::mem::align_of::<FaultCommandSlotV1>() == 64);
const _: () = assert!(core::mem::size_of::<FaultResultSlotV1>() == FAULT_RESULT_SLOT_V1_BYTES);
const _: () = assert!(core::mem::align_of::<FaultResultSlotV1>() == 64);
const _: () =
    assert!(core::mem::size_of::<FaultPayloadArenaHeader>() == FAULT_PAYLOAD_ARENA_HEADER_BYTES);
const _: () = assert!(core::mem::align_of::<FaultPayloadArenaHeader>() == 128);
const _: () = assert!(FAULT_COMMAND_SLOT_RESERVATION_START_OFFSET == 0);
const _: () = assert!(FAULT_COMMAND_SLOT_PAYLOAD_START_OFFSET == 8);
const _: () = assert!(FAULT_COMMAND_SLOT_RESERVATION_END_OFFSET == 16);
const _: () = assert!(FAULT_COMMAND_SLOT_HEADER_OFFSET == 24);
const _: () = assert!(FAULT_RESULT_SLOT_RESERVATION_START_OFFSET == 0);
const _: () = assert!(FAULT_RESULT_SLOT_PAYLOAD_START_OFFSET == 8);
const _: () = assert!(FAULT_RESULT_SLOT_RESERVATION_END_OFFSET == 16);
const _: () = assert!(FAULT_RESULT_SLOT_HEADER_OFFSET == 24);
const _: () = assert!(FAULT_PAYLOAD_ARENA_READ_CURSOR_OFFSET == 0);
const _: () = assert!(FAULT_PAYLOAD_ARENA_WRITE_CURSOR_OFFSET == 64);
