//! Result dequeue that reuses caller-owned payload storage.

use super::*;

/// One attempt to remove a result while retaining caller-owned payload storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BufferedFaultResultPoll {
    /// No result is ready; the unchanged payload buffer is returned to the caller.
    Pending(Vec<u8>),
    /// One result was removed using the caller-owned payload buffer.
    Ready(DequeuedFaultResult),
}

/// Removes one result using an already-owned payload buffer.
///
/// This variant lets a caller reserve result storage before publishing an
/// architecturally visible command. It never grows `payload_buffer`: a result
/// larger than its existing capacity fails closed while retaining the ring
/// entry for diagnosis and retry policy.
///
/// # Errors
///
/// Returns [`FaultTransportError`] when consumer admission is held, or for
/// invalid capacity, corrupt indices, inconsistent reservation framing, an
/// undersized caller buffer, or arithmetic overflow.
pub fn dequeue_fault_result_with_buffer(
    ring: &RingHeader,
    slots: &[FaultResultSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &[u8],
    arena_region_offset: u64,
    mut payload_buffer: Vec<u8>,
) -> Result<BufferedFaultResultPoll, FaultTransportError> {
    let _consumer = ring
        .enter_consumer()
        .ok_or(FaultTransportError::ConsumerBarrierHeld)?;
    let Some((head, slot_index)) = consumer_ring_slot(ring, slots.len())? else {
        return Ok(BufferedFaultResultPoll::Pending(payload_buffer));
    };
    let slot = slots[slot_index];
    copy_reserved_payload_into(
        arena_header,
        arena,
        slot.reservation_start,
        slot.payload_start,
        slot.reservation_end,
        &mut payload_buffer,
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
        header.authenticate_payload(&payload_buffer)?;
        Ok(header)
    });

    arena_header
        .read_cursor
        .store(slot.reservation_end, Ordering::Release);
    ring.read_idx.store(head.wrapping_add(1), Ordering::Release);

    Ok(BufferedFaultResultPoll::Ready(match decoded {
        Ok(header) => DequeuedFaultResult::Valid {
            header,
            payload: payload_buffer,
        },
        Err(error) => DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        },
    }))
}

fn copy_reserved_payload_into(
    header: &FaultPayloadArenaHeader,
    arena: &[u8],
    start: u64,
    payload_start: u64,
    end: u64,
    owned: &mut Vec<u8>,
) -> Result<(), FaultTransportError> {
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
    if owned.capacity() < payload_len {
        return Err(FaultTransportError::PayloadBufferTooSmall {
            capacity: owned.capacity(),
            requested: payload_len,
        });
    }
    owned.clear();
    owned.extend_from_slice(payload);
    Ok(())
}
