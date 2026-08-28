//! Fault command and result SPSC transport operations.

use super::*;

#[path = "transport/buffered_result.rs"]
mod buffered_result;
pub use buffered_result::*;

/// One command removed from the transport after its arena reservation is freed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DequeuedFaultCommand {
    /// The envelope and copied payload passed every ABI check.
    Valid {
        /// Decoded command envelope.
        header: Box<FaultCommandHeaderV1>,
        /// Owned payload bytes, no longer borrowed from shared memory.
        payload: Vec<u8>,
    },
    /// The transport framing was sound but the command ABI was rejected.
    Rejected {
        /// Raw kind tag, preserved even when it is not registered.
        raw_command_kind: u16,
        /// Raw sequence, preserved for a canonical result when nonzero.
        command_sequence: u64,
        /// Exact ABI validation failure.
        error: FaultAbiError,
    },
}

/// Enqueues one command and payload with release publication.
///
/// The operation first proves that both the command ring and circular byte
/// arena have capacity. It then copies the payload, writes the complete slot,
/// publishes the arena cursor, and finally publishes the ring index. A failure
/// before publication changes neither shared cursor.
///
/// `arena_region_offset` is the byte offset of `arena` from the shared region
/// base and is encoded into the command header.
///
/// # Errors
///
/// Returns [`FaultTransportError`] when a capacity, index, payload, arithmetic,
/// or command-envelope invariant is violated.
pub fn enqueue_fault_command(
    ring: &RingHeader,
    slots: &mut [FaultCommandSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &mut [u8],
    arena_region_offset: u64,
    mut header: FaultCommandHeaderV1,
    payload: &[u8],
) -> Result<(), FaultTransportError> {
    let _producer = ring
        .enter_producer()
        .ok_or(FaultTransportError::ProducerBarrierHeld)?;
    let (tail, slot_index) = producer_ring_slot(ring, slots.len())?;
    let reservation = reserve_arena(arena_header, arena.len(), payload.len())?;
    copy_payload(arena, reservation.payload_start, payload)?;

    header.payload_offset = if payload.is_empty() {
        0
    } else {
        arena_region_offset
            .checked_add(reservation.payload_start % arena_len_u64(arena.len())?)
            .ok_or(FaultTransportError::ArithmeticOverflow)?
    };
    header.payload_length = u32::try_from(payload.len())
        .map_err(|_| FaultTransportError::PayloadTooLarge { len: payload.len() })?;
    header.payload_hash = *blake3::hash(payload).as_bytes();
    header.validate().map_err(FaultTransportError::Abi)?;

    slots[slot_index] = FaultCommandSlotV1 {
        reservation_start: reservation.start,
        payload_start: reservation.payload_start,
        reservation_end: reservation.end,
        header: header.encode(),
        _reserved: [0; 16],
    };
    arena_header
        .write_cursor
        .store(reservation.end, Ordering::Release);
    ring.write_idx
        .store(tail.wrapping_add(1), Ordering::Release);
    Ok(())
}

/// Removes one command, copies its payload, and releases its transport space.
///
/// ABI-invalid commands are returned as [`DequeuedFaultCommand::Rejected`] and
/// still consume their sound transport reservation, preventing a malformed
/// host command from wedging the plugin. Corrupt transport-owned framing fails
/// loudly because advancing an untrusted cursor would risk releasing live data.
///
/// # Errors
///
/// Returns [`FaultTransportError`] for invalid capacity, corrupt indices,
/// inconsistent reservation framing, allocation refusal, or arithmetic overflow.
pub fn dequeue_fault_command(
    ring: &RingHeader,
    slots: &[FaultCommandSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &[u8],
    arena_region_offset: u64,
) -> Result<Option<DequeuedFaultCommand>, FaultTransportError> {
    let Some((head, slot_index)) = consumer_ring_slot(ring, slots.len())? else {
        return Ok(None);
    };
    let slot = slots[slot_index];
    let payload = copy_reserved_payload(
        arena_header,
        arena,
        slot.reservation_start,
        slot.payload_start,
        slot.reservation_end,
    )?;
    let raw_command_kind = read_raw_u16(&slot.header, FAULT_COMMAND_KIND_OFFSET);
    let command_sequence = read_raw_u64(&slot.header, FAULT_COMMAND_SEQUENCE_OFFSET);
    let decoded = FaultCommandHeaderV1::decode_header(&slot.header).and_then(|header| {
        validate_envelope_reservation(
            header.payload_offset,
            header.payload_length,
            arena_region_offset,
            arena.len(),
            slot.payload_start,
            slot.reservation_end,
        )?;
        header.authenticate_payload(&payload)?;
        Ok(header)
    });

    arena_header
        .read_cursor
        .store(slot.reservation_end, Ordering::Release);
    ring.read_idx.store(head.wrapping_add(1), Ordering::Release);

    Ok(Some(match decoded {
        Ok(header) => DequeuedFaultCommand::Valid {
            header: Box::new(header),
            payload,
        },
        Err(error) => DequeuedFaultCommand::Rejected {
            raw_command_kind,
            command_sequence,
            error,
        },
    }))
}

/// One result removed from the transport after its arena reservation is freed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DequeuedFaultResult {
    /// The result envelope and copied evidence payload passed every ABI check.
    Valid {
        /// Decoded result envelope.
        header: FaultResultHeaderV1,
        /// Owned result payload bytes.
        payload: Vec<u8>,
    },
    /// A malformed result was consumed and must fail the run loudly.
    Invalid {
        /// Raw command sequence for diagnostics and correlation.
        command_sequence: u64,
        /// Exact ABI validation failure.
        error: FaultAbiError,
    },
}

/// Enqueues one QEMU result and payload with release publication.
///
/// # Errors
///
/// Returns [`FaultTransportError`] when ring or arena capacity is exhausted, a
/// cursor is corrupt, arithmetic overflows, or the result violates its ABI.
pub fn enqueue_fault_result(
    ring: &RingHeader,
    slots: &mut [FaultResultSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &mut [u8],
    arena_region_offset: u64,
    mut header: FaultResultHeaderV1,
    payload: &[u8],
) -> Result<(), FaultTransportError> {
    let _producer = ring
        .enter_producer()
        .ok_or(FaultTransportError::ProducerBarrierHeld)?;
    let (tail, slot_index) = producer_ring_slot(ring, slots.len())?;
    let reservation = reserve_arena(arena_header, arena.len(), payload.len())?;
    copy_payload(arena, reservation.payload_start, payload)?;

    header.result_offset = if payload.is_empty() {
        0
    } else {
        arena_region_offset
            .checked_add(reservation.payload_start % arena_len_u64(arena.len())?)
            .ok_or(FaultTransportError::ArithmeticOverflow)?
    };
    header.result_length = u32::try_from(payload.len())
        .map_err(|_| FaultTransportError::PayloadTooLarge { len: payload.len() })?;
    header.result_payload_hash = *blake3::hash(payload).as_bytes();
    FaultResultHeaderV1::decode_header(&header.encode()).map_err(FaultTransportError::Abi)?;

    slots[slot_index] = FaultResultSlotV1 {
        reservation_start: reservation.start,
        payload_start: reservation.payload_start,
        reservation_end: reservation.end,
        header: header.encode(),
        _reserved: [0; 44],
    };
    arena_header
        .write_cursor
        .store(reservation.end, Ordering::Release);
    ring.write_idx
        .store(tail.wrapping_add(1), Ordering::Release);
    Ok(())
}

/// Reports whether one result payload can be published without mutation.
///
/// This preflight is exact for the single plugin producer: it checks the same
/// ring slot and contiguous arena reservation used by [`enqueue_fault_result`]
/// but advances no cursor. The caller must serialize preflight and enqueue.
///
/// # Errors
///
/// Returns [`FaultTransportError`] for invalid capacities, corrupt cursors,
/// payloads above the hard bound, or arithmetic overflow. Ordinary ring or
/// arena backpressure returns `Ok(false)`.
pub fn can_enqueue_fault_result(
    ring: &RingHeader,
    slots: &[FaultResultSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &[u8],
    payload_len: usize,
) -> Result<bool, FaultTransportError> {
    match producer_ring_slot(ring, slots.len()) {
        Ok((_tail, _slot)) => {}
        Err(FaultTransportError::RingFull { .. }) => return Ok(false),
        Err(error) => return Err(error),
    }
    match reserve_arena(arena_header, arena.len(), payload_len) {
        Ok(_reservation) => Ok(true),
        Err(FaultTransportError::PayloadArenaFull { .. }) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Removes one result, copies its payload, and releases its transport space.
///
/// Sound transport framing is consumed even when the result ABI is invalid so
/// a bad plugin result cannot permanently fill the ring. The returned invalid
/// value is a mandatory run failure, never a simulated guest outcome.
///
/// # Errors
///
/// Returns [`FaultTransportError`] for invalid capacity, corrupt indices,
/// inconsistent reservation framing, allocation refusal, or arithmetic overflow.
pub fn dequeue_fault_result(
    ring: &RingHeader,
    slots: &[FaultResultSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &[u8],
    arena_region_offset: u64,
) -> Result<Option<DequeuedFaultResult>, FaultTransportError> {
    let Some((head, slot_index)) = consumer_ring_slot(ring, slots.len())? else {
        return Ok(None);
    };
    let slot = slots[slot_index];
    let payload = copy_reserved_payload(
        arena_header,
        arena,
        slot.reservation_start,
        slot.payload_start,
        slot.reservation_end,
    )?;
    let command_sequence = read_raw_u64(&slot.header, FAULT_RESULT_SEQUENCE_OFFSET);
    let decoded = FaultResultHeaderV1::decode_header(&slot.header).and_then(|header| {
        validate_envelope_reservation(
            header.result_offset,
            header.result_length,
            arena_region_offset,
            arena.len(),
            slot.payload_start,
            slot.reservation_end,
        )?;
        header.authenticate_payload(&payload)?;
        Ok(header)
    });

    arena_header
        .read_cursor
        .store(slot.reservation_end, Ordering::Release);
    ring.read_idx.store(head.wrapping_add(1), Ordering::Release);

    Ok(Some(match decoded {
        Ok(header) => DequeuedFaultResult::Valid { header, payload },
        Err(error) => DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        },
    }))
}

#[derive(Clone, Copy)]
pub(crate) struct ArenaReservation {
    pub(crate) start: u64,
    pub(crate) payload_start: u64,
    pub(crate) end: u64,
}

pub(crate) fn producer_ring_slot(
    ring: &RingHeader,
    capacity: usize,
) -> Result<(u64, usize), FaultTransportError> {
    let capacity = validated_transport_capacity(capacity)?;
    let tail = ring.write_idx.load(Ordering::Relaxed);
    let head = ring.read_idx.load(Ordering::Acquire);
    let live = tail.wrapping_sub(head);
    if live > capacity {
        return Err(FaultTransportError::CorruptRingIndices {
            read: head,
            write: tail,
            capacity,
        });
    }
    if live == capacity {
        return Err(FaultTransportError::RingFull { capacity });
    }
    Ok((tail, (tail & (capacity - 1)) as usize))
}

pub(crate) fn consumer_ring_slot(
    ring: &RingHeader,
    capacity: usize,
) -> Result<Option<(u64, usize)>, FaultTransportError> {
    let capacity = validated_transport_capacity(capacity)?;
    let head = ring.read_idx.load(Ordering::Relaxed);
    let tail = ring.write_idx.load(Ordering::Acquire);
    let live = tail.wrapping_sub(head);
    if live > capacity {
        return Err(FaultTransportError::CorruptRingIndices {
            read: head,
            write: tail,
            capacity,
        });
    }
    Ok((live != 0).then_some((head, (head & (capacity - 1)) as usize)))
}

fn validated_transport_capacity(capacity: usize) -> Result<u64, FaultTransportError> {
    if capacity == 0
        || !capacity.is_power_of_two()
        || capacity > HARD_FAULT_COMMAND_CAPACITY as usize
    {
        return Err(FaultTransportError::InvalidRingCapacity { capacity });
    }
    Ok(capacity as u64)
}

fn arena_len_u64(len: usize) -> Result<u64, FaultTransportError> {
    if len == 0 || len > HARD_FAULT_PAYLOAD_BYTES as usize {
        return Err(FaultTransportError::InvalidArenaCapacity { capacity: len });
    }
    u64::try_from(len).map_err(|_| FaultTransportError::ArithmeticOverflow)
}

pub(crate) fn reserve_arena(
    header: &FaultPayloadArenaHeader,
    arena_len: usize,
    payload_len: usize,
) -> Result<ArenaReservation, FaultTransportError> {
    let capacity = arena_len_u64(arena_len)?;
    let payload_len_usize = payload_len;
    let payload_len = u64::try_from(payload_len)
        .map_err(|_| FaultTransportError::PayloadTooLarge { len: payload_len })?;
    if payload_len > capacity || payload_len > u64::from(HARD_FAULT_PAYLOAD_BYTES) {
        return Err(FaultTransportError::PayloadTooLarge {
            len: payload_len_usize,
        });
    }
    let write = header.write_cursor.load(Ordering::Relaxed);
    let read = header.read_cursor.load(Ordering::Acquire);
    let live = write.wrapping_sub(read);
    if live > capacity {
        return Err(FaultTransportError::CorruptArenaCursors {
            read,
            write,
            capacity,
        });
    }
    if payload_len == 0 {
        return Ok(ArenaReservation {
            start: write,
            payload_start: write,
            end: write,
        });
    }
    let physical = write % capacity;
    let remaining = capacity - physical;
    let padding = if payload_len > remaining {
        remaining
    } else {
        0
    };
    let reservation_len = padding
        .checked_add(payload_len)
        .ok_or(FaultTransportError::ArithmeticOverflow)?;
    if live
        .checked_add(reservation_len)
        .ok_or(FaultTransportError::ArithmeticOverflow)?
        > capacity
    {
        return Err(FaultTransportError::PayloadArenaFull {
            requested: reservation_len,
            available: capacity - live,
        });
    }
    let payload_start = write
        .checked_add(padding)
        .ok_or(FaultTransportError::ArithmeticOverflow)?;
    let end = payload_start
        .checked_add(payload_len)
        .ok_or(FaultTransportError::ArithmeticOverflow)?;
    Ok(ArenaReservation {
        start: write,
        payload_start,
        end,
    })
}

pub(crate) fn copy_payload(
    arena: &mut [u8],
    logical_start: u64,
    payload: &[u8],
) -> Result<(), FaultTransportError> {
    if payload.is_empty() {
        return Ok(());
    }
    let capacity = arena_len_u64(arena.len())?;
    let start = usize::try_from(logical_start % capacity)
        .map_err(|_| FaultTransportError::ArithmeticOverflow)?;
    let end = start
        .checked_add(payload.len())
        .ok_or(FaultTransportError::ArithmeticOverflow)?;
    let destination = arena
        .get_mut(start..end)
        .ok_or(FaultTransportError::CorruptReservation)?;
    destination.copy_from_slice(payload);
    Ok(())
}

pub(crate) fn copy_reserved_payload(
    header: &FaultPayloadArenaHeader,
    arena: &[u8],
    start: u64,
    payload_start: u64,
    end: u64,
) -> Result<Vec<u8>, FaultTransportError> {
    let capacity = arena_len_u64(arena.len())?;
    let expected_start = header.read_cursor.load(Ordering::Relaxed);
    let published_end = header.write_cursor.load(Ordering::Acquire);
    if start != expected_start
        || payload_start < start
        || end < payload_start
        || end.wrapping_sub(start) > capacity
        || end > published_end
    {
        return Err(FaultTransportError::CorruptReservation);
    }
    let physical_start = usize::try_from(payload_start % capacity)
        .map_err(|_| FaultTransportError::ArithmeticOverflow)?;
    let payload_len = usize::try_from(end - payload_start)
        .map_err(|_| FaultTransportError::ArithmeticOverflow)?;
    let physical_end = physical_start
        .checked_add(payload_len)
        .ok_or(FaultTransportError::ArithmeticOverflow)?;
    let payload = arena
        .get(physical_start..physical_end)
        .ok_or(FaultTransportError::CorruptReservation)?;
    let mut owned = Vec::new();
    owned.try_reserve_exact(payload_len).map_err(|_| {
        FaultTransportError::PayloadAllocationFailed {
            requested: payload_len,
        }
    })?;
    owned.extend_from_slice(payload);
    Ok(owned)
}

pub(crate) fn validate_envelope_reservation(
    payload_offset: u64,
    payload_length: u32,
    arena_region_offset: u64,
    arena_len: usize,
    payload_start: u64,
    reservation_end: u64,
) -> Result<(), FaultAbiError> {
    if payload_length == 0 {
        return (payload_offset == 0 && payload_start == reservation_end)
            .then_some(())
            .ok_or(FaultAbiError::PayloadBounds);
    }
    let capacity = u64::try_from(arena_len).map_err(|_| FaultAbiError::PayloadBounds)?;
    let expected_offset = arena_region_offset
        .checked_add(payload_start % capacity)
        .ok_or(FaultAbiError::PayloadBounds)?;
    if payload_offset != expected_offset
        || reservation_end.wrapping_sub(payload_start) != u64::from(payload_length)
    {
        return Err(FaultAbiError::PayloadBounds);
    }
    Ok(())
}

pub(crate) fn publish_transport_write(
    ring: &RingHeader,
    arena_header: &FaultPayloadArenaHeader,
    tail: u64,
    reservation_end: u64,
) {
    arena_header
        .write_cursor
        .store(reservation_end, Ordering::Release);
    ring.write_idx
        .store(tail.wrapping_add(1), Ordering::Release);
}

pub(crate) fn publish_transport_read(
    ring: &RingHeader,
    arena_header: &FaultPayloadArenaHeader,
    head: u64,
    reservation_end: u64,
) {
    arena_header
        .read_cursor
        .store(reservation_end, Ordering::Release);
    ring.read_idx.store(head.wrapping_add(1), Ordering::Release);
}

fn read_raw_u16(bytes: &[u8], offset: usize) -> u16 {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| <[u8; 2]>::try_from(value).ok())
        .map(u16::from_le_bytes)
        .unwrap_or(0)
}

fn read_raw_u64(bytes: &[u8], offset: usize) -> u64 {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| <[u8; 8]>::try_from(value).ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

pub(super) fn payload_slice(
    region: &[u8],
    offset: u64,
    length: u32,
) -> Result<&[u8], FaultAbiError> {
    let start = usize::try_from(offset).map_err(|_| FaultAbiError::PayloadBounds)?;
    let length = usize::try_from(length).map_err(|_| FaultAbiError::PayloadBounds)?;
    let end = start
        .checked_add(length)
        .ok_or(FaultAbiError::PayloadBounds)?;
    region.get(start..end).ok_or(FaultAbiError::PayloadBounds)
}
