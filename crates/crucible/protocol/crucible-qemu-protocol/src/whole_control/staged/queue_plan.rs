//! Source-issued queue-plan byte encoding and checked shared-region geometry.
//!
//! The plan correlates source observations with actual constructor-bound queues.
//! It carries no private native handle and cannot mint source custody or Ready.
//!
//! ```text
//! header128: CWHLQUE\0, edition2:u32, extent:u32, scope[32], epoch/process/barrier/
//!            region:u64, role_count:u32, reserved0:u32, raw/ps/offset:u64,
//!            instruction_ps50:u32, units_ps1:u32, reserved0:u64
//! role80: extent:u32, role:u16, reserved0:u16, ring/source/target/capacity:u32,
//!         generation/header_offset/entries_offset:u64, entry_stride4640:u32,
//!         header_size128:u32, node/port/lane_lengths:u16, reserved0:u16,
//!         transport_epoch/producer_frontier:u64, node[N], port[P], lane[L]
//! Integers are big endian. Native pointers and callback tables stay process local.
//! ```

use super::{QUEUE_PLAN_HEADER_BYTES, QUEUE_PLAN_ROLE_BYTES};
use crate::whole_control::{
    WHOLE_BODY_MAX_BYTES, WholeControlError, domain_digest, inventory::WholeQueueRole, put_u32,
    put_u64, read_u32, read_u64,
};

/// Borrows the entire original source-issued queue and clock plan.
pub struct QueuePlan<'a> {
    body: &'a [u8],
    /// Correlates the original process-protocol world scope.
    pub scope: [u8; 32],
    /// Retains the source-issued native world epoch.
    pub native_epoch: u64,
    /// Retains the genuine native process generation.
    pub process_generation: u64,
    /// Retains the genuine original native barrier generation.
    pub barrier_generation: u64,
    /// Bounds checked references inside the same original mapped region.
    pub region_byte_length: u64,
    /// Retains the actual raw native retirement coordinate.
    pub native_raw: u64,
    /// Retains the actual native semantic clock in picoseconds.
    pub semantic_ps: u64,
    /// Retains the authentic raw-to-semantic offset in picoseconds.
    pub logical_offset_ps: u64,
}

impl<'a> QueuePlan<'a> {
    /// Validates complete plan shape and every checked region reference.
    ///
    /// # Errors
    /// Rejects malformed or duplicate roles, reserved fields, overflowing or
    /// overlapping regions, absent correlations and unsupported clock profiles.
    /// A native constructor separately joins these bytes to its original sources.
    pub fn decode(body: &'a [u8]) -> Result<Self, WholeControlError> {
        if !(QUEUE_PLAN_HEADER_BYTES..=WHOLE_BODY_MAX_BYTES as usize).contains(&body.len())
            || body[..8] != *b"CWHLQUE\0"
            || read_u32(body, 8) != 2
            || read_u32(body, 12) as usize != body.len()
            || body[16..48] == [0; 32]
            || [48, 56, 64, 72]
                .into_iter()
                .any(|offset| read_u64(body, offset) == 0)
            || !(1..=6).contains(&read_u32(body, 80))
            || read_u32(body, 84) != 0
            || read_u32(body, 112) != 50
            || read_u32(body, 116) != 1
            || read_u64(body, 120) != 0
            || read_u64(body, 96) > i64::MAX as u64
            || !read_u64(body, 96).is_multiple_of(50)
            || read_u64(body, 88)
                .checked_mul(50)
                .and_then(|raw_ps| raw_ps.checked_add(read_u64(body, 104)))
                != Some(read_u64(body, 96))
        {
            return Err(WholeControlError::Body);
        }
        let mut remaining = &body[QUEUE_PLAN_HEADER_BYTES..];
        let mut roles = 0u8;
        let region = read_u64(body, 72);
        for _ in 0..read_u32(body, 80) {
            let (record, extent) = decode_role(remaining)?;
            let role = record.role as u16;
            if roles & (1 << role) != 0 {
                return Err(WholeControlError::Body);
            }
            roles |= 1 << role;
            record.validate_region_spans(region)?;
            // At most six actual roles exist. Compare all earlier spans before
            // exposing any role, including independently valid foreign offsets.
            let mut earlier = &body[QUEUE_PLAN_HEADER_BYTES..body.len() - remaining.len()];
            while !earlier.is_empty() {
                let (previous, used) = decode_role(earlier)?;
                if record.ring_index == previous.ring_index || record.overlaps(&previous)? {
                    return Err(WholeControlError::Body);
                }
                earlier = &earlier[used..];
            }
            remaining = &remaining[extent..];
        }
        if !remaining.is_empty() {
            return Err(WholeControlError::Body);
        }
        Ok(Self {
            body,
            scope: array32(body, 16),
            native_epoch: read_u64(body, 48),
            process_generation: read_u64(body, 56),
            barrier_generation: read_u64(body, 64),
            region_byte_length: region,
            native_raw: read_u64(body, 88),
            semantic_ps: read_u64(body, 96),
            logical_offset_ps: read_u64(body, 104),
        })
    }

    /// Borrows the same entire immutable original plan body.
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Commits all complete same original plan bytes.
    pub fn digest(&self) -> [u8; 32] {
        domain_digest(b"crucible.qemu.whole.queue-plan.v2\0", self.body)
    }

    /// Iterates checked original roles without creating a replacement roster.
    pub fn roles(&self) -> QueuePlanRoles<'a> {
        QueuePlanRoles {
            remaining: &self.body[QUEUE_PLAN_HEADER_BYTES..],
        }
    }
}

/// Borrows one source-issued physical queue binding and original logical IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueRole<'a> {
    /// Selects an actually supported native input or output operation.
    pub role: WholeQueueRole,
    /// Selects the original physical directed-ring index.
    pub ring_index: u32,
    /// Retains the original physical producer slot.
    pub source_slot: u32,
    /// Retains the original physical consumer slot.
    pub target_slot: u32,
    /// Retains the same original ring's constructor capacity.
    pub capacity: u32,
    /// Correlates the actual registered ring owner incarnation.
    pub generation: u64,
    /// Selects the checked header offset within the original mapping.
    pub header_offset: u64,
    /// Selects the checked frame backing within that same mapping.
    pub entries_offset: u64,
    /// Retains the actual source-issued block transport epoch, when applicable.
    pub transport_epoch: u64,
    /// Retains the original source's request or queue frontier, by role.
    pub producer_frontier: u64,
    /// Names the original host logical node under the advertised ASCII profile.
    pub node: &'a str,
    /// Names the originally advertised port.
    pub port: &'a str,
    /// Names the originally advertised lane.
    pub lane: &'a str,
}

impl QueueRole<'_> {
    /// Encodes the complete role into exact-size preallocated backing.
    ///
    /// # Errors
    /// Rejects malformed identities, generations, geometry or backing extent.
    pub fn encode_into(&self, body: &mut [u8]) -> Result<(), WholeControlError> {
        let identifiers = [self.node, self.port, self.lane];
        let extent = identifiers
            .iter()
            .try_fold(QUEUE_PLAN_ROLE_BYTES, |total, id| {
                total.checked_add(id.len())
            });
        if extent != Some(body.len()) || identifiers.iter().any(|id| !(1..=128).contains(&id.len()))
        {
            return Err(WholeControlError::Body);
        }
        body.fill(0);
        put_u32(body, 0, body.len() as u32);
        body[4..6].copy_from_slice(&(self.role as u16).to_be_bytes());
        for (offset, value) in [
            (8, self.ring_index),
            (12, self.source_slot),
            (16, self.target_slot),
            (20, self.capacity),
            (48, 4640),
            (52, 128),
        ] {
            put_u32(body, offset, value);
        }
        for (offset, value) in [
            (24, self.generation),
            (32, self.header_offset),
            (40, self.entries_offset),
            (64, self.transport_epoch),
            (72, self.producer_frontier),
        ] {
            put_u64(body, offset, value);
        }
        let mut offset = QUEUE_PLAN_ROLE_BYTES;
        for (index, id) in identifiers.into_iter().enumerate() {
            body[56 + index * 2..58 + index * 2].copy_from_slice(&(id.len() as u16).to_be_bytes());
            body[offset..offset + id.len()].copy_from_slice(id.as_bytes());
            offset += id.len();
        }
        decode_role(body)?;
        Ok(())
    }

    /// Checks both public spans inside the authentic mapping extent.
    ///
    /// # Errors
    /// Rejects overflow, misalignment, overlap or references outside that extent.
    pub fn validate_region_spans(&self, region: u64) -> Result<(), WholeControlError> {
        let spans = self.spans()?;
        if !self.header_offset.is_multiple_of(128)
            || !self.entries_offset.is_multiple_of(8)
            || spans.iter().any(|(_, end)| *end > region)
            || overlap(spans[0], spans[1])
        {
            return Err(WholeControlError::Body);
        }
        Ok(())
    }

    fn spans(&self) -> Result<[(u64, u64); 2], WholeControlError> {
        Ok([
            (
                self.header_offset,
                self.header_offset
                    .checked_add(128)
                    .ok_or(WholeControlError::Body)?,
            ),
            (
                self.entries_offset,
                u64::from(self.capacity)
                    .checked_mul(4640)
                    .and_then(|extent| self.entries_offset.checked_add(extent))
                    .ok_or(WholeControlError::Body)?,
            ),
        ])
    }

    fn overlaps(&self, other: &Self) -> Result<bool, WholeControlError> {
        let ours = self.spans()?;
        let theirs = other.spans()?;
        Ok(ours
            .into_iter()
            .any(|a| theirs.into_iter().any(|b| overlap(a, b))))
    }
}

/// Iterates a complete previously validated original source roster.
pub struct QueuePlanRoles<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for QueuePlanRoles<'a> {
    type Item = QueueRole<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let (role, extent) = decode_role(self.remaining).ok()?;
        self.remaining = &self.remaining[extent..];
        Some(role)
    }
}

fn decode_role(body: &[u8]) -> Result<(QueueRole<'_>, usize), WholeControlError> {
    if body.len() < QUEUE_PLAN_ROLE_BYTES {
        return Err(WholeControlError::Body);
    }
    let extent = read_u32(body, 0) as usize;
    let lengths = [56, 58, 60].map(|offset| read_u16(body, offset) as usize);
    if extent > body.len()
        || lengths
            .into_iter()
            .try_fold(QUEUE_PLAN_ROLE_BYTES, |sum, length| sum.checked_add(length))
            != Some(extent)
        || lengths.iter().any(|length| !(1..=128).contains(length))
        || read_u16(body, 6) != 0
        || read_u16(body, 62) != 0
        || read_u32(body, 20) == 0
        || read_u64(body, 24) == 0
        || read_u32(body, 48) != 4640
        || read_u32(body, 52) != 128
    {
        return Err(WholeControlError::Body);
    }
    let role = match read_u16(body, 4) {
        1 => WholeQueueRole::PacketDelivery,
        2 => WholeQueueRole::BlockCompletion,
        3 => WholeQueueRole::ReadonlyNinePCompletion,
        4 => WholeQueueRole::PacketPublication,
        5 => WholeQueueRole::BlockRequest,
        6 => WholeQueueRole::ReadonlyNinePRequest,
        _ => return Err(WholeControlError::Body),
    };
    let mut offset = QUEUE_PLAN_ROLE_BYTES;
    let mut identifier = |length| {
        let value = std::str::from_utf8(&body[offset..offset + length])
            .map_err(|_| WholeControlError::Body)?;
        offset += length;
        let mut bytes = value.bytes();
        if !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
        {
            return Err(WholeControlError::Body);
        }
        Ok(value)
    };
    Ok((
        QueueRole {
            role,
            ring_index: read_u32(body, 8),
            source_slot: read_u32(body, 12),
            target_slot: read_u32(body, 16),
            capacity: read_u32(body, 20),
            generation: read_u64(body, 24),
            header_offset: read_u64(body, 32),
            entries_offset: read_u64(body, 40),
            transport_epoch: read_u64(body, 64),
            producer_frontier: read_u64(body, 72),
            node: identifier(lengths[0])?,
            port: identifier(lengths[1])?,
            lane: identifier(lengths[2])?,
        },
        extent,
    ))
}

fn overlap(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

fn array32(body: &[u8], offset: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(&body[offset..offset + 32]);
    value
}

fn read_u16(body: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([body[offset], body[offset + 1]])
}
