//! Validated stable shared-memory fault transports.

use super::*;

pub(super) struct StableFaultCommandTransport {
    pub(super) ring: NonNull<RingHeader>,
    pub(super) slots: NonNull<FaultCommandSlotV1>,
    pub(super) slot_count: usize,
    pub(super) arena_header: NonNull<FaultPayloadArenaHeader>,
    pub(super) arena: NonNull<u8>,
    pub(super) arena_len: usize,
    pub(super) arena_region_offset: u64,
}

pub(super) struct StableFaultResultTransport {
    pub(super) ring: NonNull<RingHeader>,
    pub(super) slots: NonNull<FaultResultSlotV2>,
    pub(super) slot_count: usize,
    pub(super) arena_header: NonNull<FaultPayloadArenaHeader>,
    pub(super) arena: NonNull<u8>,
    pub(super) arena_len: usize,
    pub(super) arena_region_offset: u64,
}

pub(super) struct StableFaultEventTransport {
    pub(super) ring: NonNull<RingHeader>,
    pub(super) slots: NonNull<FaultEventSlotV1>,
    pub(super) slot_count: usize,
    pub(super) arena_header: NonNull<FaultPayloadArenaHeader>,
    pub(super) arena: NonNull<u8>,
    pub(super) arena_len: usize,
    pub(super) arena_region_offset: u64,
}

impl StableFaultCommandTransport {
    pub(super) fn new(
        view: MappedFaultCommandTransportMut<'_>,
    ) -> Result<Self, FaultCommandBridgeError> {
        Ok(Self {
            ring: NonNull::from(view.ring),
            slots: NonNull::new(view.slots.as_mut_ptr()).ok_or(
                FaultCommandBridgeError::EmptyTransport {
                    direction: "command",
                },
            )?,
            slot_count: view.slots.len(),
            arena_header: NonNull::from(view.arena_header),
            arena: NonNull::new(view.arena.as_mut_ptr()).ok_or(
                FaultCommandBridgeError::EmptyTransport {
                    direction: "command",
                },
            )?,
            arena_len: view.arena.len(),
            arena_region_offset: view.arena_region_offset,
        })
    }

    pub(super) fn dequeue(&self) -> Result<Option<DequeuedFaultCommand>, FaultCommandBridgeError> {
        // SAFETY: the setup mapping owns every validated address for the bridge
        // lifetime. This bridge is the sole plugin consumer for this VM's SPSC
        // command ring and only reads slot/arena bytes published by the host.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                self.ring.as_ref(),
                core::slice::from_raw_parts(self.slots.as_ptr(), self.slot_count),
                self.arena_header.as_ref(),
                core::slice::from_raw_parts(self.arena.as_ptr(), self.arena_len),
            )
        };
        dequeue_fault_command(ring, slots, arena_header, arena, self.arena_region_offset)
            .map_err(|source| FaultCommandBridgeError::Transport { source })
    }

    pub(super) fn read_index(&self) -> u64 {
        // SAFETY: the setup mapping owns this validated ring header for the
        // bridge lifetime. The index accessor performs an atomic acquire load.
        unsafe { self.ring.as_ref() }.read_index()
    }

    pub(super) fn write_index(&self) -> u64 {
        // SAFETY: see `read_index`; this is the paired producer acquire load.
        unsafe { self.ring.as_ref() }.write_index()
    }
}

impl StableFaultResultTransport {
    pub(super) fn new(
        view: MappedFaultResultTransportMut<'_>,
    ) -> Result<Self, FaultCommandBridgeError> {
        Ok(Self {
            ring: NonNull::from(view.ring),
            slots: NonNull::new(view.slots.as_mut_ptr()).ok_or(
                FaultCommandBridgeError::EmptyTransport {
                    direction: "result",
                },
            )?,
            slot_count: view.slots.len(),
            arena_header: NonNull::from(view.arena_header),
            arena: NonNull::new(view.arena.as_mut_ptr()).ok_or(
                FaultCommandBridgeError::EmptyTransport {
                    direction: "result",
                },
            )?,
            arena_len: view.arena.len(),
            arena_region_offset: view.arena_region_offset,
        })
    }

    pub(super) fn enqueue(
        &mut self,
        header: FaultResultHeaderV2,
        payload: &[u8],
    ) -> Result<(), FaultCommandBridgeError> {
        // SAFETY: the setup mapping retains these validated addresses. The live
        // callback mutex makes this bridge the sole result producer, while the
        // host touches only the published SPSC read side.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                self.ring.as_ref(),
                core::slice::from_raw_parts_mut(self.slots.as_ptr(), self.slot_count),
                self.arena_header.as_ref(),
                core::slice::from_raw_parts_mut(self.arena.as_ptr(), self.arena_len),
            )
        };
        enqueue_fault_result(
            ring,
            slots,
            arena_header,
            arena,
            self.arena_region_offset,
            header,
            payload,
        )
        .map_err(|source| FaultCommandBridgeError::Transport { source })
    }

    pub(super) fn can_enqueue(&self, payload_len: usize) -> Result<bool, FaultCommandBridgeError> {
        // SAFETY: the validated setup mapping owns these addresses and the
        // callback mutex serializes this producer's preflight and enqueue.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                self.ring.as_ref(),
                core::slice::from_raw_parts(self.slots.as_ptr(), self.slot_count),
                self.arena_header.as_ref(),
                core::slice::from_raw_parts(self.arena.as_ptr(), self.arena_len),
            )
        };
        can_enqueue_fault_result(ring, slots, arena_header, arena, payload_len)
            .map_err(|source| FaultCommandBridgeError::Transport { source })
    }
}

impl StableFaultEventTransport {
    pub(super) fn new(
        view: MappedFaultEventTransportMut<'_>,
    ) -> Result<Self, FaultCommandBridgeError> {
        Ok(Self {
            ring: NonNull::from(view.ring),
            slots: NonNull::new(view.slots.as_mut_ptr())
                .ok_or(FaultCommandBridgeError::EmptyTransport { direction: "event" })?,
            slot_count: view.slots.len(),
            arena_header: NonNull::from(view.arena_header),
            arena: NonNull::new(view.arena.as_mut_ptr())
                .ok_or(FaultCommandBridgeError::EmptyTransport { direction: "event" })?,
            arena_len: view.arena.len(),
            arena_region_offset: view.arena_region_offset,
        })
    }

    pub(super) fn can_enqueue(&self, payload_len: usize) -> Result<bool, FaultCommandBridgeError> {
        // SAFETY: the validated setup mapping owns these addresses and the
        // callback mutex serializes this producer's preflight and enqueue.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                self.ring.as_ref(),
                core::slice::from_raw_parts(self.slots.as_ptr(), self.slot_count),
                self.arena_header.as_ref(),
                core::slice::from_raw_parts(self.arena.as_ptr(), self.arena_len),
            )
        };
        can_enqueue_fault_event(ring, slots, arena_header, arena, payload_len)
            .map_err(|source| FaultCommandBridgeError::Transport { source })
    }

    pub(super) fn enqueue(
        &mut self,
        header: FaultEventHeaderV1,
        payload: &[u8],
    ) -> Result<(), FaultCommandBridgeError> {
        // SAFETY: the setup mapping retains these validated addresses. The
        // callback mutex makes this bridge the sole event producer, while the
        // host touches only the published SPSC read side.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                self.ring.as_ref(),
                core::slice::from_raw_parts_mut(self.slots.as_ptr(), self.slot_count),
                self.arena_header.as_ref(),
                core::slice::from_raw_parts_mut(self.arena.as_ptr(), self.arena_len),
            )
        };
        enqueue_fault_event(
            ring,
            slots,
            arena_header,
            arena,
            self.arena_region_offset,
            header,
            payload,
        )
        .map_err(|source| FaultCommandBridgeError::Transport { source })
    }
}
