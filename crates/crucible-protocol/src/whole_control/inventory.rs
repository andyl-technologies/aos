//! Complete queue-bound inventory records for the whole-control edition.
//!
//! Fields describe original bytes and checked process-protocol offsets. They
//! supply neither queue ownership nor native admission. An installed provider
//! matches every record to its constructor-bound ring, current frontier and
//! original request token before any queue or guest effect.
//!
//! ```text
//! inventory: count:u32, reserved:u32, record[count]
//! record: fixed big-endian header[216], node[N], port[P], lane[L], media[M],
//!         common_envelope[C], complete_frame_payload[B]
//! fixed fields: extent0:u32, role4:u16, reserved6:u16, ring8/source12/target16/
//!               frame_seq20:u32, generation24/read32/write40/transport_epoch48/
//!               native_id56/time_ps64/microstep72:u64, phase80/reserved82/
//!               node_len84/port_len86/lane_len88/media_len90:u16,
//!               common_len92/payload_len96:u32, delivery_state100/reserved102:u16,
//!               ring_offset104/entries_offset112:u64, capacity120/attempts124:u32,
//!               content_digest128[32], last_attempt160:u64, common_digest168[32],
//!               frame_delivery_icount200/reserved208:u64
//! The outer whole-control edition selects this inventory layout. Empty is
//! eight zero bytes; it never certifies actual empty native queues.
//! ```

use super::{WHOLE_BODY_MAX_BYTES, WholeControlError, put_u32, put_u64, read_u32, read_u64};
use sha2::{Digest, Sha256};

/// Counts the closed inventory prefix.
pub const WHOLE_INVENTORY_HEADER_BYTES: usize = 8;
/// Counts one complete fixed queue-record header.
pub const WHOLE_QUEUE_RECORD_HEADER_BYTES: usize = 216;
/// Bounds payloads by the public shared-memory frame profile.
pub const WHOLE_QUEUE_PAYLOAD_MAX_BYTES: usize = 4608;

/// Selects an actual queue operation without copying a native enum layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum WholeQueueRole {
    /// Stages a complete router packet for original guest RX acceptance.
    PacketDelivery = 1,
    /// Stages a response for an original pending guest block request.
    BlockCompletion = 2,
    /// Stages a reply for an original pending read-only 9p request.
    ReadonlyNinePCompletion = 3,
    /// Retains an actual packet published by a guest TX callback.
    PacketPublication = 4,
    /// Retains an actual request published by a guest block callback.
    BlockRequest = 5,
    /// Retains an actual request published by a read-only 9p callback.
    ReadonlyNinePRequest = 6,
}

impl WholeQueueRole {
    /// Reports whether this role enters the guest-facing input queues.
    pub const fn is_input(self) -> bool {
        matches!(
            self,
            Self::PacketDelivery | Self::BlockCompletion | Self::ReadonlyNinePCompletion
        )
    }
}

/// Borrows the entire immutable portable identity and payload of one queue record.
///
/// Original common envelope bytes retain the complete Delivery or publication
/// and its referenced evidence bodies. Their digest is correlation only. The
/// Apache owner validates its actual producer lineage separately; GPL queue
/// admission must never infer authority from this opaque common envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WholeQueueRecord<'a> {
    /// Selects the constructor-bound physical queue operation.
    pub role: WholeQueueRole,
    /// Selects the original directed-ring index.
    pub ring_index: u32,
    /// Names the producer slot in the original mapping.
    pub source_slot: u32,
    /// Names the consumer slot in the original mapping.
    pub target_slot: u32,
    /// Preserves the frame's native transport sequence.
    pub frame_sequence: u32,
    /// Correlates the same registered mapping's ring incarnation.
    pub ring_generation: u64,
    /// Preserves the original absolute consumer frontier.
    pub read_index: u64,
    /// Preserves the original absolute producer frontier.
    pub write_index: u64,
    /// Correlates an original pending block or 9p transport epoch.
    pub transport_epoch: u64,
    /// Correlates the actual retained native request token.
    pub native_id: u64,
    /// Preserves the common delivery or publication physical coordinate.
    pub time_ps: u64,
    /// Preserves causal same-time ordering independently of native icount.
    pub microstep: u64,
    /// Selects the explicit public phase: Publication one or Delivery two.
    pub phase: u16,
    /// Preserves Pending zero or Retained one from the public frame ABI.
    pub delivery_state: u16,
    /// Selects the checked header offset inside the original mapped region.
    pub ring_offset: u64,
    /// Selects the checked entries offset inside that same mapped region.
    pub entries_offset: u64,
    /// Retains the constructor-bound ring capacity.
    pub capacity: u32,
    /// Preserves actual consumer delivery-attempt history.
    pub delivery_attempts: u32,
    /// Preserves the actual last consumer attempt's native coordinate.
    pub last_attempt_icount: u64,
    /// Preserves the original in-band native visibility coordinate.
    pub frame_delivery_icount: u64,
    /// Names the original common logical endpoint's node.
    pub node: &'a str,
    /// Names its constructor-selected port.
    pub port: &'a str,
    /// Names its original input or output lane.
    pub lane: &'a str,
    /// Preserves the original ContentRef's bounded media type.
    pub media_type: &'a str,
    /// Preserves complete original common envelope and evidence bytes.
    pub common_envelope: &'a [u8],
    /// Preserves the entire native frame payload, including its wire headers.
    pub payload: &'a [u8],
}

impl WholeQueueRecord<'_> {
    /// Encodes one complete record into exact-size caller-owned backing.
    ///
    /// # Errors
    /// Rejects unrepresentable extents or malformed complete record data. A
    /// refused record remains private to its caller; it must never be published.
    pub fn encode_into(&self, bytes: &mut [u8]) -> Result<(), WholeControlError> {
        let strings = [self.node, self.port, self.lane, self.media_type];
        let extent = strings
            .iter()
            .try_fold(WHOLE_QUEUE_RECORD_HEADER_BYTES, |extent, string| {
                extent.checked_add(string.len())
            })
            .and_then(|extent| extent.checked_add(self.common_envelope.len()))
            .and_then(|extent| extent.checked_add(self.payload.len()));
        if extent != Some(bytes.len())
            || bytes.len() > WHOLE_BODY_MAX_BYTES as usize
            || strings
                .iter()
                .any(|string| !(1..=128).contains(&string.len()))
        {
            return Err(WholeControlError::Body);
        }
        bytes.fill(0);
        put_u32(bytes, 0, bytes.len() as u32);
        put_u16(bytes, 4, self.role as u16);
        for (offset, value) in [
            (8, self.ring_index),
            (12, self.source_slot),
            (16, self.target_slot),
            (20, self.frame_sequence),
            (120, self.capacity),
            (124, self.delivery_attempts),
        ] {
            put_u32(bytes, offset, value);
        }
        for (offset, value) in [
            (24, self.ring_generation),
            (32, self.read_index),
            (40, self.write_index),
            (48, self.transport_epoch),
            (56, self.native_id),
            (64, self.time_ps),
            (72, self.microstep),
            (104, self.ring_offset),
            (112, self.entries_offset),
            (160, self.last_attempt_icount),
            (200, self.frame_delivery_icount),
        ] {
            put_u64(bytes, offset, value);
        }
        put_u16(bytes, 80, self.phase);
        put_u16(bytes, 100, self.delivery_state);
        for (index, string) in strings.iter().enumerate() {
            put_u16(bytes, 84 + 2 * index, string.len() as u16);
        }
        put_u32(bytes, 92, self.common_envelope.len() as u32);
        put_u32(bytes, 96, self.payload.len() as u32);
        bytes[128..160].copy_from_slice(&cnp_blob_digest(self.payload));
        bytes[168..200].copy_from_slice(&Sha256::digest(self.common_envelope));
        let mut offset = WHOLE_QUEUE_RECORD_HEADER_BYTES;
        for part in strings
            .iter()
            .map(|string| string.as_bytes())
            .chain([self.common_envelope, self.payload])
        {
            bytes[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }
        decode_record(bytes)?;
        Ok(())
    }

    /// Checks public ring and entry spans inside an actually owned region extent.
    ///
    /// # Errors
    /// Rejects overflow, misalignment, overlapping spans or offsets outside the
    /// supplied region. The provider separately authenticates that real mapping,
    /// its constructor-bound role, generation and live frontier before effects.
    pub fn validate_region_spans(&self, region_bytes: u64) -> Result<(), WholeControlError> {
        // These sizes and alignments belong to the public frame/ring ABI.
        let ring_end = self
            .ring_offset
            .checked_add(128)
            .ok_or(WholeControlError::Body)?;
        let entries_end = u64::from(self.capacity)
            .checked_mul(4640)
            .and_then(|bytes| self.entries_offset.checked_add(bytes))
            .ok_or(WholeControlError::Body)?;
        if !self.ring_offset.is_multiple_of(128)
            || !self.entries_offset.is_multiple_of(8)
            || ring_end > region_bytes
            || entries_end > region_bytes
            || (self.ring_offset < entries_end && self.entries_offset < ring_end)
        {
            return Err(WholeControlError::Body);
        }
        Ok(())
    }
}

/// Borrows one complete inventory after validating every retained record.
#[derive(Clone, Debug)]
pub struct WholeInventory<'a> {
    body: &'a [u8],
    count: u32,
}

impl<'a> WholeInventory<'a> {
    /// Validates the entire inventory before exposing any queue operation.
    ///
    /// # Errors
    /// Rejects truncated or trailing bytes, unsupported roles or directions,
    /// overflow, malformed identifiers, changed payloads, reserved fields or
    /// records outside the outer whole body allowance.
    pub fn decode(body: &'a [u8], input: bool) -> Result<Self, WholeControlError> {
        if body.len() < WHOLE_INVENTORY_HEADER_BYTES
            || body.len() > WHOLE_BODY_MAX_BYTES as usize
            || read_u32(body, 4) != 0
        {
            return Err(WholeControlError::Body);
        }
        let count = read_u32(body, 0);
        if count as usize
            > (body.len() - WHOLE_INVENTORY_HEADER_BYTES) / WHOLE_QUEUE_RECORD_HEADER_BYTES
        {
            return Err(WholeControlError::Body);
        }
        let mut remaining = &body[WHOLE_INVENTORY_HEADER_BYTES..];
        for _ in 0..count {
            let (record, consumed) = decode_record(remaining)?;
            if record.role.is_input() != input {
                return Err(WholeControlError::Body);
            }
            remaining = &remaining[consumed..];
        }
        if !remaining.is_empty() {
            return Err(WholeControlError::Body);
        }
        Ok(Self { body, count })
    }

    /// Returns the exact retained record count independently of byte credit.
    pub const fn record_count(&self) -> u32 {
        self.count
    }

    /// Borrows records in the original frozen inventory order.
    pub fn records(&self) -> WholeInventoryRecords<'a> {
        WholeInventoryRecords {
            remaining: &self.body[WHOLE_INVENTORY_HEADER_BYTES..],
            count: self.count,
        }
    }
}

/// Iterates already validated complete borrowed queue records without allocation.
pub struct WholeInventoryRecords<'a> {
    remaining: &'a [u8],
    count: u32,
}

impl<'a> Iterator for WholeInventoryRecords<'a> {
    type Item = WholeQueueRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        let (record, consumed) = decode_record(self.remaining).ok()?;
        self.remaining = &self.remaining[consumed..];
        self.count -= 1;
        Some(record)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.count as usize, Some(self.count as usize))
    }
}

fn decode_record(bytes: &[u8]) -> Result<(WholeQueueRecord<'_>, usize), WholeControlError> {
    if bytes.len() < WHOLE_QUEUE_RECORD_HEADER_BYTES {
        return Err(WholeControlError::Body);
    }
    let extent = read_u32(bytes, 0) as usize;
    if extent < WHOLE_QUEUE_RECORD_HEADER_BYTES || extent > bytes.len() {
        return Err(WholeControlError::Body);
    }
    let bytes = &bytes[..extent];
    let role = match read_u16(bytes, 4) {
        1 => WholeQueueRole::PacketDelivery,
        2 => WholeQueueRole::BlockCompletion,
        3 => WholeQueueRole::ReadonlyNinePCompletion,
        4 => WholeQueueRole::PacketPublication,
        5 => WholeQueueRole::BlockRequest,
        6 => WholeQueueRole::ReadonlyNinePRequest,
        _ => return Err(WholeControlError::Body),
    };
    if [6, 82, 102]
        .into_iter()
        .any(|offset| read_u16(bytes, offset) != 0)
        || read_u64(bytes, 208) != 0
        || read_u64(bytes, 24) == 0
        || read_u32(bytes, 120) == 0
        || read_u64(bytes, 40) < read_u64(bytes, 32)
        || read_u64(bytes, 40) - read_u64(bytes, 32) > u64::from(read_u32(bytes, 120))
        || read_u16(bytes, 80) != if role.is_input() { 2 } else { 1 }
        || read_u16(bytes, 100) > 1
        || read_u64(bytes, 64) > i64::MAX as u64
        || !read_u64(bytes, 64).is_multiple_of(50)
        || (role.is_input() && read_u64(bytes, 72) != 0)
    {
        return Err(WholeControlError::Body);
    }

    let lengths = [84, 86, 88, 90].map(|offset| read_u16(bytes, offset) as usize);
    if lengths
        .into_iter()
        .any(|length| !(1..=128).contains(&length))
    {
        return Err(WholeControlError::Body);
    }
    let common_len = read_u32(bytes, 92) as usize;
    let payload_len = read_u32(bytes, 96) as usize;
    if common_len == 0 || payload_len == 0 || payload_len > WHOLE_QUEUE_PAYLOAD_MAX_BYTES {
        return Err(WholeControlError::Body);
    }
    let total = lengths
        .into_iter()
        .try_fold(WHOLE_QUEUE_RECORD_HEADER_BYTES, |total, length| {
            total.checked_add(length)
        })
        .and_then(|total| total.checked_add(common_len))
        .and_then(|total| total.checked_add(payload_len));
    if total != Some(extent) {
        return Err(WholeControlError::Body);
    }
    let mut offset = WHOLE_QUEUE_RECORD_HEADER_BYTES;
    let mut string = |length| {
        let value = std::str::from_utf8(&bytes[offset..offset + length])
            .map_err(|_| WholeControlError::Body)?;
        offset += length;
        Ok::<_, WholeControlError>(value)
    };
    let node = string(lengths[0])?;
    let port = string(lengths[1])?;
    let lane = string(lengths[2])?;
    let media_type = string(lengths[3])?;
    for identifier in [node, port, lane] {
        let mut characters = identifier.bytes();
        if !characters
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !characters.all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        {
            return Err(WholeControlError::Body);
        }
    }
    if !media_type.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(WholeControlError::Body);
    }
    let common_envelope = &bytes[offset..offset + common_len];
    let payload = &bytes[offset + common_len..];
    if Sha256::digest(common_envelope).as_slice() != &bytes[168..200]
        || cnp_blob_digest(payload) != bytes[128..160]
    {
        return Err(WholeControlError::Correlation);
    }

    Ok((
        WholeQueueRecord {
            role,
            ring_index: read_u32(bytes, 8),
            source_slot: read_u32(bytes, 12),
            target_slot: read_u32(bytes, 16),
            frame_sequence: read_u32(bytes, 20),
            ring_generation: read_u64(bytes, 24),
            read_index: read_u64(bytes, 32),
            write_index: read_u64(bytes, 40),
            transport_epoch: read_u64(bytes, 48),
            native_id: read_u64(bytes, 56),
            time_ps: read_u64(bytes, 64),
            microstep: read_u64(bytes, 72),
            phase: read_u16(bytes, 80),
            delivery_state: read_u16(bytes, 100),
            ring_offset: read_u64(bytes, 104),
            entries_offset: read_u64(bytes, 112),
            capacity: read_u32(bytes, 120),
            delivery_attempts: read_u32(bytes, 124),
            last_attempt_icount: read_u64(bytes, 160),
            frame_delivery_icount: read_u64(bytes, 200),
            node,
            port,
            lane,
            media_type,
            common_envelope,
            payload,
        },
        extent,
    ))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn cnp_blob_digest(payload: &[u8]) -> [u8; 32] {
    // This is the public CNP/1 blob construction, independent of native ownership.
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&11_u32.to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&(payload.len() as u64).to_be_bytes());
    hash.update(payload);
    *hash.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Wire geometry controls panic on invalid fixtures or failed invariants.
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn blob_commitment_matches_independent_original_host_frame_and_cnp_apis() {
        let payload = include_bytes!("testdata/host-frame-payload.bin");
        let digest = include_bytes!("testdata/host-frame-cnp-digest.bin");
        // Emitted separately by the actual public FrameEntry constructor and
        // host canonical::hash/ContentRef::verify APIs, without this codec.
        assert_eq!(&cnp_blob_digest(payload), digest);
        let mut original = record();
        original.payload = payload;
        let bytes = encoded(&original);
        assert_eq!(&bytes[8 + 128..8 + 160], digest);
        assert_eq!(
            WholeInventory::decode(&bytes, true)
                .unwrap()
                .records()
                .next()
                .unwrap(),
            original
        );
    }

    fn record() -> WholeQueueRecord<'static> {
        WholeQueueRecord {
            role: WholeQueueRole::PacketDelivery,
            ring_index: 2,
            source_slot: 0,
            target_slot: 1,
            frame_sequence: 9,
            ring_generation: 7,
            read_index: 0,
            write_index: 1,
            transport_epoch: 0,
            native_id: 0,
            time_ps: 250,
            microstep: 0,
            phase: 2,
            delivery_state: 0,
            ring_offset: 8192,
            entries_offset: 16384,
            capacity: 2,
            delivery_attempts: 0,
            last_attempt_icount: 0,
            frame_delivery_icount: 17,
            node: "vm/1",
            port: "packet",
            lane: "rx",
            media_type: "application/octet-stream",
            common_envelope: b"{}",
            payload: b"abcdefghijklmnop",
        }
    }

    fn encoded(record: &WholeQueueRecord<'_>) -> Vec<u8> {
        let extent = WHOLE_QUEUE_RECORD_HEADER_BYTES
            + record.node.len()
            + record.port.len()
            + record.lane.len()
            + record.media_type.len()
            + record.common_envelope.len()
            + record.payload.len();
        let mut bytes = vec![0; WHOLE_INVENTORY_HEADER_BYTES + extent];
        put_u32(&mut bytes, 0, 1);
        record
            .encode_into(&mut bytes[WHOLE_INVENTORY_HEADER_BYTES..])
            .unwrap();
        bytes
    }

    #[test]
    fn zero_record_inventory_matches_native_eight_zero_byte_fixture() {
        let native_request = include_bytes!("testdata/native-zero-request.bin");
        let inventory = &native_request[super::super::WHOLE_REQUEST_HEADER_BYTES..];
        assert_eq!(inventory, [0; 8]);
        assert_eq!(
            WholeInventory::decode(inventory, true)
                .unwrap()
                .record_count(),
            0
        );
        assert_eq!(
            WholeInventory::decode(inventory, false)
                .unwrap()
                .records()
                .count(),
            0
        );
    }

    #[test]
    fn complete_record_preserves_native_counter_separately_from_common_position() {
        let original = record();
        let bytes = encoded(&original);
        let inventory = WholeInventory::decode(&bytes, true).unwrap();
        let decoded = inventory.records().next().unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.frame_delivery_icount, 17);
        assert_eq!(decoded.time_ps, 250);
        decoded.validate_region_spans(32768).unwrap();
        assert!(WholeInventory::decode(&bytes, false).is_err());
    }

    #[test]
    fn complete_decode_rejects_every_truncation_and_reserved_field_change() {
        let bytes = encoded(&record());
        for extent in 0..bytes.len() {
            assert!(WholeInventory::decode(&bytes[..extent], true).is_err());
        }
        for offset in [6, 82, 102, 208, 215] {
            let mut changed = bytes.clone();
            changed[WHOLE_INVENTORY_HEADER_BYTES + offset] ^= 1;
            assert!(WholeInventory::decode(&changed, true).is_err());
        }
        let mut changed = bytes;
        changed.push(0);
        assert!(WholeInventory::decode(&changed, true).is_err());
    }

    #[test]
    fn checked_region_spans_refuse_overflow_overlap_and_misalignment() {
        let mut original = record();
        original.ring_offset = u64::MAX;
        assert!(original.validate_region_spans(u64::MAX).is_err());
        original = record();
        original.entries_offset = original.ring_offset;
        assert!(original.validate_region_spans(32768).is_err());
        original = record();
        original.entries_offset += 1;
        assert!(original.validate_region_spans(32768).is_err());
        original = record();
        assert!(original.validate_region_spans(16385).is_err());
    }

    #[test]
    fn modified_full_payload_and_common_envelope_refuse_before_record_exposure() {
        let bytes = encoded(&record());
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(matches!(
            WholeInventory::decode(&changed, true),
            Err(WholeControlError::Correlation)
        ));
        changed = bytes;
        changed[WHOLE_INVENTORY_HEADER_BYTES + 168] ^= 1;
        assert!(matches!(
            WholeInventory::decode(&changed, true),
            Err(WholeControlError::Correlation)
        ));
    }
}
