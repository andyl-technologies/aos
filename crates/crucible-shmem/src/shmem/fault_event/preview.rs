//! Non-consuming authenticated fault-event inspection.

use core::sync::atomic::Ordering;

use super::*;

/// Mutable aggregate limits used while copying a non-consuming event preview.
///
/// The running byte coordinate is shared across staged and shared-memory
/// owners so neither source can independently spend the same configured
/// event-log allowance.
pub struct FaultEventPreviewBudget<'a> {
    /// Running canonical event-log byte usage.
    pub canonical_payload_bytes: &'a mut usize,
    /// Authored aggregate event-log byte ceiling.
    pub configured_payload_bytes: usize,
    /// Authored per-event inline-payload byte ceiling.
    pub configured_inline_payload_bytes: usize,
}

/// Returns the number of published events without consuming them.
///
/// # Errors
///
/// Returns [`FaultTransportError`] when the event-ring capacity or indices are
/// invalid.
pub fn fault_event_count(
    ring: &RingHeader,
    slots: &[FaultEventSlotV1],
) -> Result<usize, FaultTransportError> {
    let capacity = slots.len();
    if capacity == 0 || !capacity.is_power_of_two() || capacity > HARD_FAULT_EVENT_CAPACITY as usize
    {
        return Err(FaultTransportError::InvalidRingCapacity { capacity });
    }
    let head = ring.read_idx.load(Ordering::Relaxed);
    let tail = ring.write_idx.load(Ordering::Acquire);
    let live = tail.wrapping_sub(head);
    if live > capacity as u64 {
        return Err(FaultTransportError::CorruptRingIndices {
            read: head,
            write: tail,
            capacity: capacity as u64,
        });
    }
    usize::try_from(live).map_err(|_| FaultTransportError::ArithmeticOverflow)
}

/// Authenticates and copies every published event without moving transport cursors.
///
/// `destination` must have enough unused capacity for the complete published
/// prefix. This requirement makes the inspection allocation-free at the outer
/// collection boundary; each bounded payload copy remains fallible. The SPSC
/// consumer retains ownership, so a host crash before durable intent publication
/// leaves the original events available to the surviving QEMU continuation.
/// Aggregate byte accounting charges the canonical fixed header plus payload
/// for each event, matching the production event-log resource definition.
///
/// # Errors
///
/// Returns [`FaultEventError`] for corrupt transport geometry, insufficient
/// pre-reserved destination storage, invalid slot framing, or payload
/// authentication failure.
pub fn snapshot_fault_events(
    ring: &RingHeader,
    slots: &[FaultEventSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &[u8],
    arena_region_offset: u64,
    destination: &mut Vec<DequeuedFaultEvent>,
    budget: FaultEventPreviewBudget<'_>,
) -> Result<(), FaultEventError> {
    let live = fault_event_count(ring, slots)?;
    let available = destination.capacity().saturating_sub(destination.len());
    if available < live {
        return Err(FaultEventError::PreviewCapacity {
            available,
            required: live,
        });
    }
    if arena.is_empty() || arena.len() > HARD_FAULT_PAYLOAD_BYTES as usize {
        return Err(FaultTransportError::InvalidArenaCapacity {
            capacity: arena.len(),
        }
        .into());
    }
    let arena_capacity =
        u64::try_from(arena.len()).map_err(|_| FaultTransportError::ArithmeticOverflow)?;
    let head = ring.read_idx.load(Ordering::Relaxed);
    let published_end = arena_header.write_cursor();
    let mut expected_start = arena_header.read_cursor();
    for offset in 0..live {
        let logical = head.wrapping_add(
            u64::try_from(offset).map_err(|_| FaultTransportError::ArithmeticOverflow)?,
        );
        let index = usize::try_from(logical & (slots.len() as u64 - 1))
            .map_err(|_| FaultTransportError::ArithmeticOverflow)?;
        let slot = &slots[index];
        if slot.reservation_start != expected_start
            || slot.payload_start < slot.reservation_start
            || slot.reservation_end < slot.payload_start
            || slot.reservation_end.wrapping_sub(slot.reservation_start) > arena_capacity
            || slot.reservation_end > published_end
        {
            return Err(FaultTransportError::CorruptReservation.into());
        }
        let payload_length = usize::try_from(slot.reservation_end - slot.payload_start)
            .map_err(|_| FaultTransportError::ArithmeticOverflow)?;
        let physical_start = usize::try_from(slot.payload_start % arena_capacity)
            .map_err(|_| FaultTransportError::ArithmeticOverflow)?;
        let physical_end = physical_start
            .checked_add(payload_length)
            .ok_or(FaultTransportError::ArithmeticOverflow)?;
        let payload = arena
            .get(physical_start..physical_end)
            .ok_or(FaultTransportError::CorruptReservation)?;
        let header = FaultEventHeaderV1::decode_header(&slot.header)?;
        validate_envelope_reservation(
            header.payload_offset,
            header.payload_length,
            arena_region_offset,
            arena.len(),
            slot.payload_start,
            slot.reservation_end,
        )
        .map_err(FaultTransportError::Abi)?;
        header.authenticate_payload(payload)?;
        if payload.len() > budget.configured_inline_payload_bytes {
            return Err(FaultEventError::PreviewInlinePayloadCapacity {
                requested: u64::try_from(payload.len()).unwrap_or(u64::MAX),
                configured: u64::try_from(budget.configured_inline_payload_bytes)
                    .unwrap_or(u64::MAX),
            });
        }
        let record_bytes = payload
            .len()
            .checked_add(FAULT_EVENT_HEADER_V1_BYTES)
            .ok_or(FaultTransportError::ArithmeticOverflow)?;
        let admitted = budget.canonical_payload_bytes.checked_add(record_bytes);
        if admitted.is_none_or(|total| total > budget.configured_payload_bytes) {
            return Err(FaultEventError::PreviewPayloadCapacity {
                current: u64::try_from(*budget.canonical_payload_bytes).unwrap_or(u64::MAX),
                requested: u64::try_from(record_bytes).unwrap_or(u64::MAX),
                configured: u64::try_from(budget.configured_payload_bytes).unwrap_or(u64::MAX),
            });
        }
        let mut owned = Vec::new();
        owned.try_reserve_exact(payload.len()).map_err(|_| {
            FaultEventError::PreviewPayloadCapacity {
                current: u64::try_from(*budget.canonical_payload_bytes).unwrap_or(u64::MAX),
                requested: u64::try_from(record_bytes).unwrap_or(u64::MAX),
                configured: u64::try_from(budget.configured_payload_bytes).unwrap_or(u64::MAX),
            }
        })?;
        owned.extend_from_slice(payload);
        destination.push(DequeuedFaultEvent {
            header,
            payload: owned,
        });
        *budget.canonical_payload_bytes = admitted.unwrap_or(budget.configured_payload_bytes);
        expected_start = slot.reservation_end;
    }
    Ok(())
}
