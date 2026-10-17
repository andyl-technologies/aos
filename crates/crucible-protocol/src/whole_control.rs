//! Negotiated whole-VM control framing and original constructor budgets.
//!
//! This independent process protocol carries data, never native function tables,
//! pointers, source tickets, or a readiness assertion. Both endpoints select it
//! before installation using the complete sealed profile and its SHA-256 digest.
//! Ordinary control framing remains a separate edition.
//!
//! ```text
//! whole frame: magic[8], edition:u32, kind:u32, body_bytes:u32, reserved:u32
//! profile: "CWHLPRO\0", edition:u32, extent:u32, scope[32], capacity:u32,
//!          body_limit:u32, thirteen u64 bounds, reserved:u64
//! all integers are big-endian; frame header = 24, profile body = 168 bytes
//! ```

#[path = "whole_control/body.rs"]
pub mod body;

#[path = "whole_control/inventory.rs"]
pub mod inventory;

#[path = "whole_control/staged.rs"]
pub mod staged;

#[cfg(test)]
#[path = "whole_control/tests.rs"]
mod tests;

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Identifies the separately negotiated whole-control envelope.
pub const WHOLE_FRAME_MAGIC: [u8; 8] = *b"CWHLCTL\0";
/// Selects whole-control envelope edition one.
pub const WHOLE_CONTROL_EDITION: u32 = 1;
/// Counts the complete whole-control frame header.
pub const WHOLE_FRAME_HEADER_BYTES: usize = 24;
/// Bounds a complete native request or result body, including its header.
pub const WHOLE_BODY_MAX_BYTES: u32 = 65_536;
/// Counts the native request header before its complete input envelope.
pub const WHOLE_REQUEST_HEADER_BYTES: usize = 256;
/// Counts the native result header before its complete output envelope.
pub const WHOLE_RESULT_HEADER_BYTES: usize = 336;
/// Counts one complete whole-control acknowledgement body.
pub const WHOLE_ACK_BYTES: usize = 128;
/// Counts the complete constructor profile body.
pub const WHOLE_PROFILE_BYTES: usize = 168;
/// Bounds the constructor-selected number of never-recycled operations.
pub const WHOLE_OPERATION_MAX: u32 = 65_536;

const PROFILE_MAGIC: [u8; 8] = *b"CWHLPRO\0";
const PROFILE_DOMAIN: &[u8] = b"crucible.qemu.whole.profile.v1\0";
const MAX_NATIVE_HISTORY_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PROVIDER_HISTORY_BYTES: u64 = 32 * 1024 * 1024 * 1024;

/// Classifies complete whole-control frame bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum WholeFrameKind {
    /// Retains an original complete request before service.
    Request = 1,
    /// Offers an acknowledgement of one exact complete result.
    Acknowledgement = 2,
    /// Offers the immutable native complete or uncertain result.
    Result = 3,
}

/// Binds all nonrenewing constructor allowances for one retained world.
///
/// History capacity is selected before either endpoint installs its provider.
/// Each endpoint preallocates its actual stable slots and complete body backing
/// within its byte ceiling. The wire minima below do not certify native or Rust
/// allocation overhead. Native/source preparation must check those independently.
/// Exhaustion retains every historical body and owner; acknowledgement never
/// refunds allowances, clears world ownership, or recycles a slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WholeControlProfile {
    /// Correlates the original constructor-selected world protocol scope.
    pub scope: [u8; 32],
    /// Bounds original operation sequences from one through this capacity.
    pub operation_capacity: u32,
    /// Bounds each complete request or result body independently of totals.
    pub body_byte_limit: u32,
    /// Bounds all preallocated retained native operation storage.
    pub native_history_byte_limit: u64,
    /// Bounds all preallocated retained provider operation storage.
    pub provider_history_byte_limit: u64,
    /// Bounds actual administrative read attempts across the entire world.
    pub administrative_read_attempt_limit: u64,
    /// Bounds actual administrative bytes received across the entire world.
    pub administrative_read_byte_limit: u64,
    /// Bounds actual administrative write attempts across the entire world.
    pub administrative_write_attempt_limit: u64,
    /// Bounds actual administrative bytes offered across the entire world.
    pub administrative_write_byte_limit: u64,
    /// Retains the original host's absolute Linux CLOCK_MONOTONIC deadline.
    pub deadline_monotonic_ns: u64,
    /// Bounds aggregate offered guest CPU retirements without refunds.
    pub cpu_retirement_limit: u64,
    /// Bounds aggregate offered timer, worker, and synchronous event steps.
    pub event_step_limit: u64,
    /// Bounds aggregate offered actual input payload bytes.
    pub input_byte_limit: u64,
    /// Bounds aggregate offered actual input records.
    pub input_record_limit: u64,
    /// Bounds aggregate offered actual output payload bytes.
    pub output_byte_limit: u64,
    /// Bounds aggregate offered actual output records.
    pub output_record_limit: u64,
}

impl WholeControlProfile {
    /// Checks the closed edition's extents and minimum complete-history budget.
    ///
    /// # Errors
    /// Rejects an absent scope, unsupported capacity, oversized body, inadequate
    /// complete wire backing, zero physical deadline, or missing service budgets.
    /// This does not observe a live clock, allocate slots, or qualify custody.
    pub fn validate(&self) -> Result<(), WholeControlError> {
        let capacity = u64::from(self.operation_capacity);
        let body = u64::from(self.body_byte_limit);
        let minimum_wire_history = capacity
            .checked_mul(
                2 * body + 2 * WHOLE_ACK_BYTES as u64 + 3 * WHOLE_FRAME_HEADER_BYTES as u64,
            )
            .ok_or(WholeControlError::Budget)?;

        if self.scope == [0; 32]
            || !(1..=WHOLE_OPERATION_MAX).contains(&self.operation_capacity)
            || self.body_byte_limit <= WHOLE_RESULT_HEADER_BYTES as u32
            || self.body_byte_limit > WHOLE_BODY_MAX_BYTES
            || self.native_history_byte_limit < minimum_wire_history
            || self.native_history_byte_limit > MAX_NATIVE_HISTORY_BYTES
            || self.provider_history_byte_limit < minimum_wire_history
            || self.provider_history_byte_limit > MAX_PROVIDER_HISTORY_BYTES
            || self.administrative_read_attempt_limit < 2 * capacity
            || self.administrative_read_byte_limit
                < capacity
                    * (WHOLE_REQUEST_HEADER_BYTES
                        + 1
                        + WHOLE_ACK_BYTES
                        + 2 * WHOLE_FRAME_HEADER_BYTES) as u64
            || self.administrative_write_attempt_limit < capacity
            || self.administrative_write_byte_limit
                < capacity * (WHOLE_RESULT_HEADER_BYTES + 1 + WHOLE_FRAME_HEADER_BYTES) as u64
            || self.deadline_monotonic_ns == 0
            || self.cpu_retirement_limit == 0
            || self.event_step_limit == 0
        {
            return Err(WholeControlError::Budget);
        }
        Ok(())
    }

    /// Encodes the entire canonical profile without copying a native layout.
    ///
    /// # Errors
    /// Rejects any profile that fails [`Self::validate`].
    pub fn encode(&self) -> Result<[u8; WHOLE_PROFILE_BYTES], WholeControlError> {
        self.validate()?;
        let mut body = [0; WHOLE_PROFILE_BYTES];
        body[..8].copy_from_slice(&PROFILE_MAGIC);
        put_u32(&mut body, 8, WHOLE_CONTROL_EDITION);
        put_u32(&mut body, 12, WHOLE_PROFILE_BYTES as u32);
        body[16..48].copy_from_slice(&self.scope);
        put_u32(&mut body, 48, self.operation_capacity);
        put_u32(&mut body, 52, self.body_byte_limit);

        let bounds = [
            self.native_history_byte_limit,
            self.provider_history_byte_limit,
            self.administrative_read_attempt_limit,
            self.administrative_read_byte_limit,
            self.administrative_write_attempt_limit,
            self.administrative_write_byte_limit,
            self.deadline_monotonic_ns,
            self.cpu_retirement_limit,
            self.event_step_limit,
            self.input_byte_limit,
            self.input_record_limit,
            self.output_byte_limit,
            self.output_record_limit,
        ];
        for (index, bound) in bounds.into_iter().enumerate() {
            put_u64(&mut body, 56 + 8 * index, bound);
        }
        Ok(body)
    }

    /// Decodes one complete closed canonical constructor profile.
    ///
    /// # Errors
    /// Rejects mismatched magic, edition, extent, reserved bytes, or budget.
    pub fn decode(body: &[u8]) -> Result<Self, WholeControlError> {
        if body.len() != WHOLE_PROFILE_BYTES
            || body[..8] != PROFILE_MAGIC
            || read_u32(body, 8) != WHOLE_CONTROL_EDITION
            || read_u32(body, 12) != WHOLE_PROFILE_BYTES as u32
            || body[160..168] != [0; 8]
        {
            return Err(WholeControlError::Profile);
        }
        let mut scope = [0; 32];
        scope.copy_from_slice(&body[16..48]);
        let profile = Self {
            scope,
            operation_capacity: read_u32(body, 48),
            body_byte_limit: read_u32(body, 52),
            native_history_byte_limit: read_u64(body, 56),
            provider_history_byte_limit: read_u64(body, 64),
            administrative_read_attempt_limit: read_u64(body, 72),
            administrative_read_byte_limit: read_u64(body, 80),
            administrative_write_attempt_limit: read_u64(body, 88),
            administrative_write_byte_limit: read_u64(body, 96),
            deadline_monotonic_ns: read_u64(body, 104),
            cpu_retirement_limit: read_u64(body, 112),
            event_step_limit: read_u64(body, 120),
            input_byte_limit: read_u64(body, 128),
            input_record_limit: read_u64(body, 136),
            output_byte_limit: read_u64(body, 144),
            output_record_limit: read_u64(body, 152),
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Commits the complete canonical profile under its distinct SHA-256 domain.
    ///
    /// # Errors
    /// Rejects a malformed profile before hashing any encoded bytes.
    pub fn digest(&self) -> Result<[u8; 32], WholeControlError> {
        Ok(domain_digest(PROFILE_DOMAIN, &self.encode()?))
    }
}

/// Encodes a header into already owned bounded frame backing.
///
/// # Errors
/// Rejects an unsupported body bound or a kind-specific body extent. It does
/// not send bytes or admit a request, result, acknowledgement, or operation.
pub fn encode_whole_frame_header(
    kind: WholeFrameKind,
    body_bytes: usize,
    body_limit: u32,
) -> Result<[u8; WHOLE_FRAME_HEADER_BYTES], WholeControlError> {
    check_body_extent(kind, body_bytes, body_limit)?;
    let mut header = [0; WHOLE_FRAME_HEADER_BYTES];
    header[..8].copy_from_slice(&WHOLE_FRAME_MAGIC);
    put_u32(&mut header, 8, WHOLE_CONTROL_EDITION);
    put_u32(&mut header, 12, kind as u32);
    put_u32(&mut header, 16, body_bytes as u32);
    Ok(header)
}

/// Decodes one exact negotiated whole header before collecting body bytes.
///
/// # Errors
/// Rejects legacy framing, unknown kinds, nonzero reserved bytes, another
/// edition, or a body outside the constructor bound. Direction and same-owner
/// request/result/ACK ordering remain obligations of the original controller.
pub fn decode_whole_frame_header(
    header: &[u8],
    body_limit: u32,
) -> Result<(WholeFrameKind, usize), WholeControlError> {
    if header.len() != WHOLE_FRAME_HEADER_BYTES
        || header[..8] != WHOLE_FRAME_MAGIC
        || read_u32(header, 8) != WHOLE_CONTROL_EDITION
        || read_u32(header, 20) != 0
    {
        return Err(WholeControlError::Envelope);
    }
    let kind = match read_u32(header, 12) {
        1 => WholeFrameKind::Request,
        2 => WholeFrameKind::Acknowledgement,
        3 => WholeFrameKind::Result,
        _ => return Err(WholeControlError::Envelope),
    };
    let extent = read_u32(header, 16) as usize;
    check_body_extent(kind, extent, body_limit)?;
    Ok((kind, extent))
}

fn check_body_extent(
    kind: WholeFrameKind,
    extent: usize,
    limit: u32,
) -> Result<(), WholeControlError> {
    let shape = match kind {
        WholeFrameKind::Request => extent > WHOLE_REQUEST_HEADER_BYTES,
        WholeFrameKind::Acknowledgement => extent == WHOLE_ACK_BYTES,
        WholeFrameKind::Result => extent > WHOLE_RESULT_HEADER_BYTES,
    };
    if limit > WHOLE_BODY_MAX_BYTES || extent > limit as usize || !shape {
        return Err(WholeControlError::Envelope);
    }
    Ok(())
}

fn domain_digest(domain: &[u8], body: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(body);
    digest.finalize().into()
}

fn put_u32(body: &mut [u8], offset: usize, value: u32) {
    body[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_u64(body: &mut [u8], offset: usize, value: u64) {
    body[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn read_u32(body: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        body[offset],
        body[offset + 1],
        body[offset + 2],
        body[offset + 3],
    ])
}

fn read_u64(body: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        body[offset],
        body[offset + 1],
        body[offset + 2],
        body[offset + 3],
        body[offset + 4],
        body[offset + 5],
        body[offset + 6],
        body[offset + 7],
    ])
}

/// Refuses malformed whole-control protocol data before collection or effects.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WholeControlError {
    /// A complete request, result, or acknowledgement has an invalid shape.
    #[error("invalid whole-operation body")]
    Body,
    /// Complete original bytes or counts differ from their retained correlation.
    #[error("whole-operation correlation refused")]
    Correlation,
    /// An uncertain original result cannot be acknowledged or turned over.
    #[error("whole-operation remains uncertain")]
    Unknown,
    /// The frame header has an unsupported edition, kind, or extent.
    #[error("invalid negotiated whole-control envelope")]
    Envelope,
    /// The complete constructor profile has a mismatched closed layout.
    #[error("invalid whole-control constructor profile")]
    Profile,
    /// The constructor budgets cannot retain the admitted complete history.
    #[error("whole-control constructor budget refused")]
    Budget,
}
