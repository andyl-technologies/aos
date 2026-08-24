//! Lossless QEMU-to-host event protocol for installed fault rules.
//!
//! Command results acknowledge rule-table transactions. Events are separate:
//! they prove that a later architecture or device opportunity actually matched
//! and what QEMU did at that opportunity. Keeping the streams separate prevents
//! an install acknowledgement from being mistaken for fault application and
//! lets the host drain events at scheduler boundaries without advancing a VM.

use core::fmt::Write as _;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR, FAULT_COMMAND_SEMANTIC_VERSION,
    FaultCommandKind, FaultPayloadArenaHeader, FaultTransportError, HARD_FAULT_PAYLOAD_BYTES,
    RingHeader, consumer_ring_slot, copy_payload, copy_reserved_payload, producer_ring_slot,
    publish_transport_read, publish_transport_write, reserve_arena, validate_envelope_reservation,
};

/// Encoded event-header byte length.
pub const FAULT_EVENT_HEADER_V1_BYTES: usize = 320;
/// Shared-memory size of one event transport slot.
pub const FAULT_EVENT_SLOT_V1_BYTES: usize = 384;
/// Event-slot reservation-start offset.
pub const FAULT_EVENT_SLOT_RESERVATION_START_OFFSET: usize = 0;
/// Event-slot payload-start offset.
pub const FAULT_EVENT_SLOT_PAYLOAD_START_OFFSET: usize = 8;
/// Event-slot reservation-end offset.
pub const FAULT_EVENT_SLOT_RESERVATION_END_OFFSET: usize = 16;
/// Event-slot encoded-header offset.
pub const FAULT_EVENT_SLOT_HEADER_OFFSET: usize = 24;
/// Event-slot reserved-byte offset.
pub const FAULT_EVENT_SLOT_RESERVED_OFFSET: usize = 344;
/// Default event-ring capacity per node.
pub const DEFAULT_FAULT_EVENT_CAPACITY: u32 = 4_096;
/// Hard event-ring capacity per node.
pub const HARD_FAULT_EVENT_CAPACITY: u32 = 65_536;

/// Architecture/device disposition proved by one event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FaultEventOutcomeV1 {
    /// A selected rule changed architectural, device, or rule-owned state.
    Applied = 1,
    /// A selected rule deliberately suppressed an operation or delivery.
    Suppressed = 2,
    /// A selected rule produced a typed corrected outcome.
    Corrected = 3,
    /// A selected rule produced a typed non-success guest/device outcome.
    Error = 4,
    /// A selected opportunity was valid but its occurrence predicate did not fire.
    Passed = 5,
    /// A stateful rule reached its explicitly modeled recovery transition.
    Recovered = 6,
}

impl FaultEventOutcomeV1 {
    fn decode(value: u16) -> Result<Self, FaultEventError> {
        match value {
            1 => Ok(Self::Applied),
            2 => Ok(Self::Suppressed),
            3 => Ok(Self::Corrected),
            4 => Ok(Self::Error),
            5 => Ok(Self::Passed),
            6 => Ok(Self::Recovered),
            _ => Err(FaultEventError::Outcome(value)),
        }
    }
}

/// Authenticated fixed envelope for one QEMU fault-rule event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultEventHeaderV1 {
    /// Command kind of the installed rule that produced the event.
    pub command_kind: FaultCommandKind,
    /// Typed disposition at the selected opportunity.
    pub outcome: FaultEventOutcomeV1,
    /// Strictly increasing per-node event sequence.
    pub event_sequence: u64,
    /// Command sequence that installed the active rule generation.
    pub rule_command_sequence: u64,
    /// Exact aggregate retired-instruction coordinate.
    pub observed_icount: u64,
    /// Original closed model phase tag.
    pub model_phase: u16,
    /// Closed resolved-target kind tag.
    pub target_kind: u16,
    /// Binding transition/rule generation.
    pub generation: u64,
    /// Canonical binding identity hash.
    pub binding_hash: [u8; 32],
    /// Exact opportunity identity, or zero only for a boundary impulse.
    pub opportunity_hash: [u8; 32],
    /// Resolved action identity installed for this generation.
    pub action_hash: [u8; 32],
    /// Resolved target identity.
    pub target_hash: [u8; 32],
    /// Before-state digest for the affected semantic state.
    pub before_hash: [u8; 32],
    /// After-state digest for the affected semantic state.
    pub after_hash: [u8; 32],
    /// SHA-256 of the complete effect-specific evidence payload.
    pub evidence_hash: [u8; 32],
    /// BLAKE3 digest authenticating the transported payload bytes.
    pub payload_hash: [u8; 32],
    /// Region-relative byte offset in the event arena.
    pub payload_offset: u64,
    /// Exact effect-specific evidence byte length.
    pub payload_length: u32,
}

impl FaultEventHeaderV1 {
    /// Encodes the canonical little-endian event header.
    #[must_use]
    pub fn encode(&self) -> [u8; FAULT_EVENT_HEADER_V1_BYTES] {
        let mut bytes = [0_u8; FAULT_EVENT_HEADER_V1_BYTES];
        let mut offset = 0;
        put_u16(&mut bytes, &mut offset, FAULT_COMMAND_ABI_MAJOR);
        put_u16(&mut bytes, &mut offset, FAULT_COMMAND_ABI_MINOR);
        put_u16(&mut bytes, &mut offset, self.command_kind as u16);
        put_u16(&mut bytes, &mut offset, self.outcome as u16);
        put_u32(&mut bytes, &mut offset, FAULT_COMMAND_SEMANTIC_VERSION);
        put_u64(&mut bytes, &mut offset, self.event_sequence);
        put_u64(&mut bytes, &mut offset, self.rule_command_sequence);
        put_u64(&mut bytes, &mut offset, self.observed_icount);
        put_u16(&mut bytes, &mut offset, self.model_phase);
        put_u16(&mut bytes, &mut offset, self.target_kind);
        put_u64(&mut bytes, &mut offset, self.generation);
        for hash in [
            self.binding_hash,
            self.opportunity_hash,
            self.action_hash,
            self.target_hash,
            self.before_hash,
            self.after_hash,
            self.evidence_hash,
            self.payload_hash,
        ] {
            bytes[offset..offset + 32].copy_from_slice(&hash);
            offset += 32;
        }
        put_u64(&mut bytes, &mut offset, self.payload_offset);
        put_u32(&mut bytes, &mut offset, self.payload_length);
        put_u32(&mut bytes, &mut offset, 0);
        debug_assert_eq!(offset, FAULT_EVENT_HEADER_V1_BYTES);
        bytes
    }

    /// Decodes and authenticates one event header and its arena payload.
    ///
    /// # Errors
    ///
    /// Returns [`FaultEventError`] for invalid versions, tags, sequences,
    /// reserved values, bounds, state invariants, or payload digests.
    pub fn decode<'a>(
        bytes: &[u8],
        payload_region: &'a [u8],
    ) -> Result<(Self, &'a [u8]), FaultEventError> {
        let value = Self::decode_header(bytes)?;
        let start = usize::try_from(value.payload_offset).map_err(|_| FaultEventError::Bounds)?;
        let length = usize::try_from(value.payload_length).map_err(|_| FaultEventError::Bounds)?;
        let end = start.checked_add(length).ok_or(FaultEventError::Bounds)?;
        let payload = payload_region
            .get(start..end)
            .ok_or(FaultEventError::Bounds)?;
        value.authenticate_payload(payload)?;
        Ok((value, payload))
    }

    fn decode_header(bytes: &[u8]) -> Result<Self, FaultEventError> {
        if bytes.len() != FAULT_EVENT_HEADER_V1_BYTES {
            return Err(FaultEventError::HeaderLength);
        }
        let mut reader = EventReader::new(bytes);
        if reader.u16()? != FAULT_COMMAND_ABI_MAJOR || reader.u16()? != FAULT_COMMAND_ABI_MINOR {
            return Err(FaultEventError::Version);
        }
        let command_kind =
            FaultCommandKind::from_u16(reader.u16()?).map_err(|_| FaultEventError::CommandKind)?;
        if matches!(
            command_kind,
            FaultCommandKind::QueryCapabilities
                | FaultCommandKind::BoundaryProbe
                | FaultCommandKind::QueryTargetManifest
        ) {
            return Err(FaultEventError::CommandKind);
        }
        let outcome = FaultEventOutcomeV1::decode(reader.u16()?)?;
        if reader.u32()? != FAULT_COMMAND_SEMANTIC_VERSION {
            return Err(FaultEventError::Version);
        }
        let value = Self {
            command_kind,
            outcome,
            event_sequence: reader.u64()?,
            rule_command_sequence: reader.u64()?,
            observed_icount: reader.u64()?,
            model_phase: reader.u16()?,
            target_kind: reader.u16()?,
            generation: reader.u64()?,
            binding_hash: reader.hash()?,
            opportunity_hash: reader.hash()?,
            action_hash: reader.hash()?,
            target_hash: reader.hash()?,
            before_hash: reader.hash()?,
            after_hash: reader.hash()?,
            evidence_hash: reader.hash()?,
            payload_hash: reader.hash()?,
            payload_offset: reader.u64()?,
            payload_length: reader.u32()?,
        };
        if reader.u32()? != 0 || !reader.exhausted() {
            return Err(FaultEventError::Reserved);
        }
        value.validate()?;
        Ok(value)
    }

    fn authenticate_payload(&self, payload: &[u8]) -> Result<(), FaultEventError> {
        if *blake3::hash(payload).as_bytes() != self.payload_hash {
            return Err(FaultEventError::PayloadDigest);
        }
        let evidence: [u8; 32] = Sha256::digest(payload).into();
        if evidence != self.evidence_hash {
            return Err(FaultEventError::EvidenceDigest);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), FaultEventError> {
        if self.event_sequence == 0
            || self.rule_command_sequence == 0
            || self.model_phase == 0
            || self.target_kind == 0
            || self.generation == 0
            || self.binding_hash == [0; 32]
            || self.action_hash == [0; 32]
            || self.target_hash == [0; 32]
            || self.payload_length == 0
            || self.payload_length > HARD_FAULT_PAYLOAD_BYTES
        {
            return Err(FaultEventError::Invariant);
        }
        if self.outcome == FaultEventOutcomeV1::Passed && self.before_hash != self.after_hash {
            return Err(FaultEventError::Invariant);
        }
        Ok(())
    }
}

/// One event slot with transport-owned circular-arena reservation cursors.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct FaultEventSlotV1 {
    reservation_start: u64,
    payload_start: u64,
    reservation_end: u64,
    header: [u8; FAULT_EVENT_HEADER_V1_BYTES],
    _reserved: [u8; 40],
}

impl FaultEventSlotV1 {
    /// Builds a zeroed unpublished event slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reservation_start: 0,
            payload_start: 0,
            reservation_end: 0,
            header: [0; FAULT_EVENT_HEADER_V1_BYTES],
            _reserved: [0; 40],
        }
    }

    pub(crate) fn write_bytes(&self, bytes: &mut [u8]) {
        bytes.fill(0);
        bytes[0..8].copy_from_slice(&self.reservation_start.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.payload_start.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.reservation_end.to_le_bytes());
        bytes[24..344].copy_from_slice(&self.header);
    }
}

impl Default for FaultEventSlotV1 {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<FaultEventSlotV1>() == FAULT_EVENT_SLOT_V1_BYTES);
const _: () = assert!(core::mem::align_of::<FaultEventSlotV1>() == 64);
const _: () = assert!(core::mem::offset_of!(FaultEventSlotV1, reservation_start) == 0);
const _: () = assert!(core::mem::offset_of!(FaultEventSlotV1, payload_start) == 8);
const _: () = assert!(core::mem::offset_of!(FaultEventSlotV1, reservation_end) == 16);
const _: () = assert!(core::mem::offset_of!(FaultEventSlotV1, header) == 24);
const _: () = assert!(core::mem::offset_of!(FaultEventSlotV1, _reserved) == 344);

/// One successfully decoded event removed from the transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DequeuedFaultEvent {
    /// Authenticated event header.
    pub header: FaultEventHeaderV1,
    /// Copied effect-specific evidence payload.
    pub payload: Vec<u8>,
}

#[path = "fault_event/checkpoint.rs"]
mod checkpoint;

/// Enqueues one event and publishes it with release ordering.
///
/// # Errors
///
/// Returns [`FaultTransportError`] for malformed geometry, a full ring,
/// exhausted payload arena, invalid offsets, or an invalid event header.
pub fn enqueue_fault_event(
    ring: &RingHeader,
    slots: &mut [FaultEventSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &mut [u8],
    arena_region_offset: u64,
    mut header: FaultEventHeaderV1,
    payload: &[u8],
) -> Result<(), FaultTransportError> {
    let (write, index) = producer_ring_slot(ring, slots.len())?;
    let reservation = reserve_arena(arena_header, arena.len(), payload.len())?;
    copy_payload(arena, reservation.payload_start, payload)?;
    header.payload_offset = arena_region_offset
        .checked_add(reservation.payload_start % arena.len() as u64)
        .ok_or(FaultTransportError::ArithmeticOverflow)?;
    header.payload_length = u32::try_from(payload.len())
        .map_err(|_| FaultTransportError::PayloadTooLarge { len: payload.len() })?;
    header.payload_hash = *blake3::hash(payload).as_bytes();
    header.evidence_hash = Sha256::digest(payload).into();
    header
        .validate()
        .map_err(|_error| FaultTransportError::Abi(crate::FaultAbiError::ResultInvariant))?;
    slots[index].reservation_start = reservation.start;
    slots[index].payload_start = reservation.payload_start;
    slots[index].reservation_end = reservation.end;
    slots[index].header = header.encode();
    publish_transport_write(ring, arena_header, write, reservation.end);
    Ok(())
}

/// Reports whether one event payload can be published without mutation.
///
/// The plugin uses this exact preflight before consuming QEMU's event head, so
/// shared-memory backpressure never loses an architectural fault occurrence.
/// The caller must serialize preflight and enqueue for this SPSC producer.
///
/// # Errors
///
/// Returns [`FaultTransportError`] for invalid capacities, corrupt cursors,
/// payloads above the hard bound, or arithmetic overflow. Ordinary ring or
/// arena backpressure returns `Ok(false)`.
pub fn can_enqueue_fault_event(
    ring: &RingHeader,
    slots: &[FaultEventSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &[u8],
    payload_len: usize,
) -> Result<bool, FaultTransportError> {
    match producer_ring_slot(ring, slots.len()) {
        Ok((_write, _slot)) => {}
        Err(FaultTransportError::RingFull { .. }) => return Ok(false),
        Err(error) => return Err(error),
    }
    match reserve_arena(arena_header, arena.len(), payload_len) {
        Ok(_reservation) => Ok(true),
        Err(FaultTransportError::PayloadArenaFull { .. }) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Reports whether a published event is waiting without consuming it.
///
/// # Errors
///
/// Returns [`FaultTransportError`] when the event-ring capacity or indices are
/// invalid.
pub fn fault_event_pending(
    ring: &RingHeader,
    slots: &[FaultEventSlotV1],
) -> Result<bool, FaultTransportError> {
    consumer_ring_slot(ring, slots.len()).map(|slot| slot.is_some())
}

/// Removes and authenticates one event without exposing arena-backed bytes.
///
/// # Errors
///
/// Returns [`FaultEventError`] for corrupt transport geometry, cursor state,
/// slot framing, event headers, or payload authentication.
pub fn dequeue_fault_event(
    ring: &RingHeader,
    slots: &mut [FaultEventSlotV1],
    arena_header: &FaultPayloadArenaHeader,
    arena: &[u8],
    arena_region_offset: u64,
) -> Result<Option<DequeuedFaultEvent>, FaultEventError> {
    let Some((read, index)) = consumer_ring_slot(ring, slots.len())? else {
        return Ok(None);
    };
    let slot = &mut slots[index];
    let reservation_end = slot.reservation_end;
    let payload = copy_reserved_payload(
        arena_header,
        arena,
        slot.reservation_start,
        slot.payload_start,
        reservation_end,
    )?;
    let header = FaultEventHeaderV1::decode_header(&slot.header)?;
    validate_envelope_reservation(
        header.payload_offset,
        header.payload_length,
        arena_region_offset,
        arena.len(),
        slot.payload_start,
        reservation_end,
    )
    .map_err(FaultTransportError::Abi)?;
    header.authenticate_payload(&payload)?;
    let value = DequeuedFaultEvent { header, payload };
    slot.header.fill(0);
    slot.reservation_start = 0;
    slot.payload_start = 0;
    slot.reservation_end = 0;
    publish_transport_read(ring, arena_header, read, reservation_end);
    Ok(Some(value))
}

fn put_u16(bytes: &mut [u8], offset: &mut usize, value: u16) {
    bytes[*offset..*offset + 2].copy_from_slice(&value.to_le_bytes());
    *offset += 2;
}
fn put_u32(bytes: &mut [u8], offset: &mut usize, value: u32) {
    bytes[*offset..*offset + 4].copy_from_slice(&value.to_le_bytes());
    *offset += 4;
}
fn put_u64(bytes: &mut [u8], offset: &mut usize, value: u64) {
    bytes[*offset..*offset + 8].copy_from_slice(&value.to_le_bytes());
    *offset += 8;
}

struct EventReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> EventReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N], FaultEventError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(FaultEventError::HeaderLength)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(FaultEventError::HeaderLength)?
            .try_into()
            .map_err(|_| FaultEventError::HeaderLength)?;
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, FaultEventError> {
        Ok(u16::from_le_bytes(self.take()?))
    }
    fn u32(&mut self) -> Result<u32, FaultEventError> {
        Ok(u32::from_le_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64, FaultEventError> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn hash(&mut self) -> Result<[u8; 32], FaultEventError> {
        self.take()
    }
    fn exhausted(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[path = "fault_event/preview.rs"]
mod preview;
#[path = "fault_event/support.rs"]
mod support;

pub use preview::{FaultEventPreviewBudget, fault_event_count, snapshot_fault_events};
pub use support::FaultEventError;
pub(crate) use support::emit_fault_event_c_header;

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "fault_event_test.rs"]
mod tests;
