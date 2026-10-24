//! Encodes factual return of one received paired Park request.
//!
//! ```text
//! CRUCPRR2/schema2[184] = binding[120] | first/post[8] | phase[4] |
//! physical resources[4] | publication count/views[8] | Original posts[8] |
//! operation/return[8] | stopped/native generations[16] | zero reserved[8]
//! ```
//!
//! Resource bits describe received native resources, and pair-view bits describe
//! received local views. Neither retires a standing publisher membership,
//! completes an operation, or issues execution permission.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::boundary_action::ActionBinding;

/// Number of bytes in a canonical paired Park terminal record.
pub const PARENT_PARK_RETURN_BYTES: usize = 184;

/// Complete resolution of the eight request-owned native resource classes.
pub const PARENT_PARK_PHYSICAL_RESOLUTION_ALL: u32 = 255;

const MAGIC: &[u8; 8] = b"CRUCPRR2";
const SCHEMA: u32 = 2;
const RETURNED_PHASE: u32 = 2;

/// Reports physical return independently of both Original observations.
///
/// This type accepts only the produced Returned phase. Pending phase1 is
/// reserved by the public contract and is not a terminal record. The exact
/// Source, transport and same-owner custody must be authenticated separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParentParkReturn {
    /// Exact Source and Park request selectors; control selectors are absent.
    pub binding: ActionBinding,
    /// Retained first operation or observation failure, independent of cleanup.
    pub first: i32,
    /// Retained independent Source post failure.
    pub post: i32,
    /// Resolution of aliases, metadata, native gates, prepared loan, QMP and ctx.
    pub physical_resolution_mask: u32,
    /// Number of planned received publication rows; zero precedes reception.
    pub publication_count: u32,
    /// Locally returned validated views, never standing publisher memberships.
    pub pair_view_return_mask: u32,
    /// Independent final actor and family Original observations, in that order.
    pub original_statuses: [i32; 2],
    /// Native operation result, independent of physical return.
    pub operation_status: i32,
    /// Native physical return result, independent of operation success.
    pub return_status: i32,
    /// Actual paused VM-stop generation received with the request.
    pub stopped_generation: u64,
    /// Actual writer-gate generation, or zero when no gate was born.
    pub native_generation: u64,
}

/// Refuses malformed or superseded paired Park terminal bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid paired Park return record")]
pub struct ParentParkReturnDecodeError;

impl ParentParkReturn {
    /// Encodes one canonical Returned record without issuing cleanup authority.
    ///
    /// # Errors
    /// Refuses control bindings, invalid coordinates, positive errno statuses,
    /// incomplete physical resolution and noncanonical received-view geometry.
    pub fn encode(self) -> Result<[u8; PARENT_PARK_RETURN_BYTES], ParentParkReturnDecodeError> {
        let binding = self.binding;
        let invalid_count =
            self.publication_count != 0 && !(2..=4).contains(&self.publication_count);
        if binding.cap == [0; 32]
            || binding.reservation == [0; 32]
            || binding.account_generation == 0
            || binding.process_generation == 0
            || binding.loan_sequence == 0
            || binding.loan_sequence & 1 != 0
            || binding.loan_sequence == u64::MAX
            || binding.token != 0
            || binding.capture.is_some()
            || !binding
                .park_request
                .is_some_and(|value| value != 0 && value != u64::MAX)
            || self.first > 0
            || self.post > 0
            || self.original_statuses.iter().any(|status| *status > 0)
            || self.operation_status > 0
            || self.return_status > 0
            || self.physical_resolution_mask != PARENT_PARK_PHYSICAL_RESOLUTION_ALL
            || invalid_count
            || self.stopped_generation == 0
            || self.stopped_generation == u64::MAX
            || self.native_generation == u64::MAX
        {
            return Err(ParentParkReturnDecodeError);
        }
        let all_views = (1_u32 << self.publication_count) - 1;
        if self.pair_view_return_mask != 0 && self.pair_view_return_mask != all_views {
            return Err(ParentParkReturnDecodeError);
        }

        let mut bytes = [0; PARENT_PARK_RETURN_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        put32(&mut bytes, 8, SCHEMA);
        put32(&mut bytes, 12, PARENT_PARK_RETURN_BYTES as u32);
        bytes[16..48].copy_from_slice(&binding.cap);
        bytes[48..80].copy_from_slice(&binding.reservation);
        put64(&mut bytes, 80, binding.account_generation);
        put64(&mut bytes, 88, binding.process_generation);
        put64(
            &mut bytes,
            96,
            binding.park_request.ok_or(ParentParkReturnDecodeError)?,
        );
        put64(&mut bytes, 104, binding.frontier);
        put64(&mut bytes, 112, binding.loan_sequence);
        put32(&mut bytes, 120, self.first as u32);
        put32(&mut bytes, 124, self.post as u32);
        put32(&mut bytes, 128, RETURNED_PHASE);
        put32(&mut bytes, 132, self.physical_resolution_mask);
        put32(&mut bytes, 136, self.publication_count);
        put32(&mut bytes, 140, self.pair_view_return_mask);
        put32(&mut bytes, 144, self.original_statuses[0] as u32);
        put32(&mut bytes, 148, self.original_statuses[1] as u32);
        put32(&mut bytes, 152, self.operation_status as u32);
        put32(&mut bytes, 156, self.return_status as u32);
        put64(&mut bytes, 160, self.stopped_generation);
        put64(&mut bytes, 168, self.native_generation);
        Ok(bytes)
    }

    /// Decodes exact terminal bytes while preserving independent signed facts.
    ///
    /// # Errors
    /// Refuses obsolete magic, Pending, changed geometry, reserved bytes and
    /// every noncanonical binding, status or resource/view field.
    pub fn decode(bytes: &[u8]) -> Result<Self, ParentParkReturnDecodeError> {
        if bytes.len() != PARENT_PARK_RETURN_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || get32(bytes, 8) != SCHEMA
            || get32(bytes, 12) != PARENT_PARK_RETURN_BYTES as u32
            || get32(bytes, 128) != RETURNED_PHASE
        {
            return Err(ParentParkReturnDecodeError);
        }
        let mut cap = [0; 32];
        cap.copy_from_slice(&bytes[16..48]);
        let mut reservation = [0; 32];
        reservation.copy_from_slice(&bytes[48..80]);
        let value = Self {
            binding: ActionBinding {
                cap,
                reservation,
                account_generation: get64(bytes, 80),
                process_generation: get64(bytes, 88),
                loan_sequence: get64(bytes, 112),
                token: 0,
                capture: None,
                park_request: Some(get64(bytes, 96)),
                frontier: get64(bytes, 104),
            },
            first: get32(bytes, 120) as i32,
            post: get32(bytes, 124) as i32,
            physical_resolution_mask: get32(bytes, 132),
            publication_count: get32(bytes, 136),
            pair_view_return_mask: get32(bytes, 140),
            original_statuses: [get32(bytes, 144) as i32, get32(bytes, 148) as i32],
            operation_status: get32(bytes, 152) as i32,
            return_status: get32(bytes, 156) as i32,
            stopped_generation: get64(bytes, 160),
            native_generation: get64(bytes, 168),
        };
        if value.encode()?.as_slice() != bytes {
            return Err(ParentParkReturnDecodeError);
        }
        Ok(value)
    }
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn get32(bytes: &[u8], offset: usize) -> u32 {
    let mut word = [0; 4];
    word.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(word)
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(word)
}

#[cfg(test)]
mod tests;
