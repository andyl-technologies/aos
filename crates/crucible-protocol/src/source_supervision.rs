//! Defines the standing Source's public live-supervision byte protocol.
//!
//! ```text
//! live[1504]: BE-u64 atomic sequence | payload[1496]
//! sealed[1520]: file device(u64) | inode(u64) | extent=1504(u64) | initial payload
//! payload header[232]:
//!   0 magic CRUCSRV3; 8 schema3(u32); 12 length1496(u32)
//!  16 supervisor cap[32]; 48 immutable monotonic origin(u64)
//!  56 outer revision(u64); 64 allowance tag; 65 sticky state; 66 zero[6]
//!  72 account generation(u64); 80 Source generation(u64)
//!  88 containing cap[32]; 120 Source reservation[32]; 152 roster revision(u64)
//! 160 cancellation device(u64); 168 inode(u64); 176 event-ID+1(u64)
//! 184 original-start allowance ns(u64); 192 roster bytes(u32); 196 zero[4]
//! 200 artifact SHA-256[32]; 232 single schema11 nanosecond roster; zero padding to600; action[896]
//! ```
//!
//! Every live word, including payload, uses atomic u64 accesses. The host
//! serializes writers and publishes an even sequence with sequentially
//! consistent operations. Readers load every word atomically and accept only
//! the same nonzero even sequence before and after; UINT64_MAX is invalidation.
//! Reader retries require the genuine containing constructor or entered
//! operation, never an invented clock. Native borrows a read-only descriptor
//! and mapping; the host sole writable mapping predates future-write sealing.
//! Syntax and matching observations issue no Source or operation authority.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::ram_control::{RAM_CONTROL_BUDGET_COUNT, RamControlBudget, decode_ram_control_budgets};

/// Fixed live file extent, including its atomic sequence word.
pub const SOURCE_SUPERVISION_BYTES: usize = 1504;
/// Fixed atomic payload extent with canonical zero padding.
pub const SOURCE_SUPERVISION_PAYLOAD_BYTES: usize = 1496;
/// Fixed sealed file corroboration and initial-observation extent.
pub const SOURCE_SUPERVISION_CORROBORATION_BYTES: usize = 1520;

const SCHEMA: u32 = 3;

/// Pure observations decoded from a standing Source publication.
///
/// No observation authenticates a descriptor, issuer or runtime assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSupervisionObservation {
    /// Exact containing supervisor identity.
    pub cap: [u8; 32],
    /// Immutable local CLOCK_MONOTONIC origin.
    pub original_monotonic_ns: u64,
    /// Current independent outer revision.
    pub outer_revision: u64,
    /// Original-start allowance, with deliberate absence preserved.
    pub allowance_ns: Option<u64>,
    /// Explicit wire state: Running0, Completed1, Expired2, Canceled3.
    pub state: u8,
    /// Already occupied native account generation.
    pub account_generation: u64,
    /// Actual Source execution generation, distinct from reservation identity.
    pub process_generation: u64,
    /// Immutable Source0 reservation identity.
    pub reservation: [u8; 32],
    /// Current Source-local canonical budget revision.
    pub roster_revision: u64,
    /// Cancellation event device, inode and normalized kernel event-ID+1.
    pub cancellation: [u64; 3],
    /// Actual selected plugin artifact digest.
    pub artifact: [u8; 32],
    /// One canonical exact-nanosecond class roster.
    pub budgets: [RamControlBudget; RAM_CONTROL_BUDGET_COUNT],
    /// Actual action observations, with dirty/partial cohorts explicitly marked.
    pub action: Option<crate::boundary_action::ActionObservation>,
}

/// Rejects malformed standing observations before native ownership checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid Source supervision publication")]
pub struct SourceSupervisionDecodeError;

/// Decodes one fixed standing payload without constructing authority.
///
/// # Errors
/// Refuses predecessor geometry, unknown flags/state, noncanonical padding,
/// invalid identities, unsupported allowance or a malformed precise roster.
pub fn decode_source_supervision_payload(
    bytes: &[u8],
) -> Result<SourceSupervisionObservation, SourceSupervisionDecodeError> {
    let invalid = SourceSupervisionDecodeError;
    if bytes.len() != SOURCE_SUPERVISION_PAYLOAD_BYTES
        || bytes[..8] != *b"CRUCSRV3"
        || u32_at(bytes, 8) != Some(SCHEMA)
        || u32_at(bytes, 12) != Some(1496)
        || bytes[64] > 1
        || bytes[65] > 3
        || bytes[66..72] != [0; 6]
        || bytes[196..200] != [0; 4]
        || bytes[16..48] == [0; 32]
        || bytes[16..48] != bytes[88..120]
        || bytes[120..152] == [0; 32]
    {
        return Err(invalid);
    }
    let allowance = u64_at(bytes, 184).ok_or(invalid)?;
    if (bytes[64] == 0 && allowance != 0)
        || (bytes[64] == 1 && (allowance == 0 || allowance > i64::MAX as u64))
    {
        return Err(invalid);
    }
    let account_generation = u64_at(bytes, 72).ok_or(invalid)?;
    let process_generation = u64_at(bytes, 80).ok_or(invalid)?;
    let event = u64_at(bytes, 176).ok_or(invalid)?;
    if account_generation == 0
        || process_generation == 0
        || !(1..=i32::MAX as u64 + 1).contains(&event)
    {
        return Err(invalid);
    }
    let roster_bytes = usize::try_from(u32_at(bytes, 192).ok_or(invalid)?).map_err(|_| invalid)?;
    let end = 232usize
        .checked_add(roster_bytes)
        .filter(|end| *end <= bytes.len())
        .ok_or(invalid)?;
    let budgets = decode_ram_control_budgets(&bytes[232..end]).map_err(|_| invalid)?;
    if end > 600 || bytes[end..600].iter().any(|byte| *byte != 0) {
        return Err(invalid);
    }
    let mut cap = [0; 32];
    cap.copy_from_slice(&bytes[16..48]);
    let mut reservation = [0; 32];
    reservation.copy_from_slice(&bytes[120..152]);
    let mut artifact = [0; 32];
    artifact.copy_from_slice(&bytes[200..232]);
    let action = if bytes[600..].iter().all(|byte| *byte == 0) {
        None
    } else {
        Some(
            crate::boundary_action::ActionObservation::decode(&bytes[600..])
                .map_err(|_| invalid)?,
        )
    };
    if action.is_some_and(|action| {
        action.binding.cap != cap
            || action.binding.reservation != reservation
            || action.binding.account_generation != account_generation
            || action.binding.process_generation != process_generation
    }) {
        return Err(invalid);
    }
    Ok(SourceSupervisionObservation {
        cap,
        reservation,
        artifact,
        account_generation,
        process_generation,
        original_monotonic_ns: u64_at(bytes, 48).ok_or(invalid)?,
        outer_revision: u64_at(bytes, 56).ok_or(invalid)?,
        allowance_ns: (bytes[64] == 1).then_some(allowance),
        state: bytes[65],
        roster_revision: u64_at(bytes, 152).ok_or(invalid)?,
        budgets,
        action,
        cancellation: [
            u64_at(bytes, 160).ok_or(invalid)?,
            u64_at(bytes, 168).ok_or(invalid)?,
            event,
        ],
    })
}

/// Checks current immutable identity and monotonic revisions against the seal.
///
/// Legitimate updates may replace budgets, allowance and sticky disposition.
/// Existing operations retain their entered clocks and captured class roster.
///
/// # Errors
/// Refuses another physical Source subject/artifact/cancellation/clock, a
/// regressed revision or an attempt to clear an already terminal disposition.
pub fn validate_source_supervision_update(
    initial: &SourceSupervisionObservation,
    live: &SourceSupervisionObservation,
) -> Result<(), SourceSupervisionDecodeError> {
    if live.cap != initial.cap
        || live.original_monotonic_ns != initial.original_monotonic_ns
        || live.account_generation != initial.account_generation
        || live.process_generation != initial.process_generation
        || live.reservation != initial.reservation
        || live.artifact != initial.artifact
        || live.cancellation != initial.cancellation
        || live.outer_revision < initial.outer_revision
        || live.roster_revision < initial.roster_revision
        || (live.roster_revision == initial.roster_revision && live.budgets != initial.budgets)
        || (live.outer_revision == initial.outer_revision
            && live.allowance_ns != initial.allowance_ns)
        || (initial.state != 0 && live.state != initial.state)
    {
        return Err(SourceSupervisionDecodeError);
    }
    Ok(())
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests;
