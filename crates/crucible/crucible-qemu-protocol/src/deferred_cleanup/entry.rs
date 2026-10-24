//! Preserves actual entry output and independent post facts, including debt.
//!
//! ```text
//! entry[1024] = header[24] | reservation[40] | request/entry incarnations[16] |
//!               zero[4] | facts[4] | first/post[8] | zero[32] | cohort[896]
//! ```
//!
//! Captured output without a reportable interval may still retain a partial
//! owner. A post cut may be recorded before the factory return is captured.
//! Neither case authenticates no-entry. A born cohort may be dirty or no longer
//! current; physical return must remain possible without querying a dead owner.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    DeferredCleanupCapability, DeferredCleanupDecodeError, DeferredCleanupIdentity,
    DeferredCleanupRequest, generation, get32, get64, header, identity, put32, put64, sequence,
    write_header,
};
use crate::boundary_action::ActionObservation;

/// Fixed extent of the factual entry report and actual cohort tail.
pub const DEFERRED_CLEANUP_ENTRY_BYTES: usize = 1024;

/// Records independent factory and post facts without inferring success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredCleanupEntryFacts {
    /// The genuine factory was attempted; every report requires this fact.
    pub attempted: bool,
    /// The factory's signed first status was actually captured.
    pub returned: bool,
    /// An actual reportable interval was born and its output captured.
    pub interval_born: bool,
    /// Actual output was captured, possibly with no reportable interval.
    pub output_captured: bool,
    /// An independent post observation was attempted.
    pub post_attempted: bool,
    /// The independent post status was actually captured.
    pub post_returned: bool,
    /// An uncertain result retains debt rather than proving no-entry.
    pub uncertain: bool,
}

impl DeferredCleanupEntryFacts {
    fn bits(self) -> u32 {
        u32::from(self.attempted)
            | u32::from(self.returned) << 1
            | u32::from(self.interval_born) << 2
            | u32::from(self.output_captured) << 3
            | u32::from(self.post_attempted) << 4
            | u32::from(self.post_returned) << 5
            | u32::from(self.uncertain) << 6
    }

    fn decode(bits: u32) -> Result<Self, DeferredCleanupDecodeError> {
        if bits & !127 != 0 {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(Self {
            attempted: bits & 1 != 0,
            returned: bits & 2 != 0,
            interval_born: bits & 4 != 0,
            output_captured: bits & 8 != 0,
            post_attempted: bits & 16 != 0,
            post_returned: bits & 32 != 0,
            uncertain: bits & 64 != 0,
        })
    }
}

/// Reports entry facts while retaining born output independently of statuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredCleanupEntry {
    /// Positive even publication sequence of this report.
    pub sequence: u64,
    /// Exact dormant reservation retained through the entry attempt.
    pub reservation: DeferredCleanupIdentity,
    /// Exact once-only request publication sequence.
    pub request_sequence: u64,
    /// Actual entered operation incarnation, present only for a known interval.
    pub entered_incarnation: Option<u64>,
    /// Independent observations, including partial and uncertain outcomes.
    pub facts: DeferredCleanupEntryFacts,
    /// Actual nonpositive first status, zero if its return was not captured.
    pub first_status: i32,
    /// Actual nonpositive post status, zero if its return was not captured.
    pub post_status: i32,
    /// Actual Cleanup primary and optional Preparation; not a Current grant.
    pub cohort: Option<ActionObservation>,
}

impl DeferredCleanupEntry {
    fn validate(&self) -> Result<(), DeferredCleanupDecodeError> {
        self.reservation.validate()?;
        if !sequence(self.sequence)
            || !sequence(self.request_sequence)
            || !self.facts.attempted
            || (self.facts.interval_born && !self.facts.output_captured)
            || (self.facts.post_returned && !self.facts.post_attempted)
            || (!self.facts.returned && self.first_status != 0)
            || (!self.facts.post_returned && self.post_status != 0)
            || self.first_status > 0
            || self.post_status > 0
            || self.facts.interval_born != self.entered_incarnation.is_some()
            || self.facts.interval_born != self.cohort.is_some()
            || self
                .entered_incarnation
                .is_some_and(|value| !generation(value))
        {
            return Err(DeferredCleanupDecodeError);
        }
        if let Some(cohort) = &self.cohort {
            cohort.encode().map_err(|_| DeferredCleanupDecodeError)?;
            if cohort.primary_count != 1
                || cohort.row_count > 2
                || cohort.projected_mask & 1 == 0
                || cohort.parents[0].class != 13
                || cohort.parents[0].preparation != if cohort.row_count == 2 { 2 } else { 0 }
            {
                return Err(DeferredCleanupDecodeError);
            }
        }
        Ok(())
    }

    /// Checks exact reservation and request correlation without granting entry.
    ///
    /// # Errors
    /// Refuses invalid records or another reservation, request or command.
    pub fn validate_for(
        &self,
        capability: &DeferredCleanupCapability,
        request: &DeferredCleanupRequest,
    ) -> Result<(), DeferredCleanupDecodeError> {
        self.validate()?;
        request.validate_for(capability)?;
        if self.reservation != capability.reservation || self.request_sequence != request.sequence {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(())
    }

    /// Encodes actual entry facts without discarding negative born outputs.
    ///
    /// # Errors
    /// Refuses inconsistent facts, unsupported statuses, absent born output,
    /// malformed cohorts or a primary other than Cleanup.
    pub fn encode(&self) -> Result<[u8; DEFERRED_CLEANUP_ENTRY_BYTES], DeferredCleanupDecodeError> {
        self.validate()?;
        let mut bytes = [0; DEFERRED_CLEANUP_ENTRY_BYTES];
        write_header(&mut bytes, b"CRUCDEN1");
        put64(&mut bytes, 16, self.sequence);
        bytes[24..56].copy_from_slice(&self.reservation.identity);
        put64(&mut bytes, 56, self.reservation.incarnation);
        put64(&mut bytes, 64, self.request_sequence);
        put64(&mut bytes, 72, self.entered_incarnation.unwrap_or(0));
        put32(&mut bytes, 84, self.facts.bits());
        put32(&mut bytes, 88, self.first_status as u32);
        put32(&mut bytes, 92, self.post_status as u32);
        if let Some(cohort) = &self.cohort {
            bytes[128..].copy_from_slice(&cohort.encode().map_err(|_| DeferredCleanupDecodeError)?);
        }
        Ok(bytes)
    }

    /// Decodes factual entry syntax, including partial or noncurrent cohorts.
    ///
    /// # Errors
    /// Refuses changed framing, nonzero padding, unknown flags, inconsistent
    /// status facts or malformed born-output and cohort associations.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeferredCleanupDecodeError> {
        header(bytes, b"CRUCDEN1", DEFERRED_CLEANUP_ENTRY_BYTES)?;
        if get32(bytes, 80) != 0 || bytes[96..128].iter().any(|value| *value != 0) {
            return Err(DeferredCleanupDecodeError);
        }
        let facts = DeferredCleanupEntryFacts::decode(get32(bytes, 84))?;
        let entered = get64(bytes, 72);
        let cohort = if facts.interval_born {
            Some(ActionObservation::decode(&bytes[128..]).map_err(|_| DeferredCleanupDecodeError)?)
        } else {
            if bytes[128..].iter().any(|value| *value != 0) {
                return Err(DeferredCleanupDecodeError);
            }
            None
        };
        let report = Self {
            sequence: get64(bytes, 16),
            reservation: identity(bytes, 24),
            request_sequence: get64(bytes, 64),
            entered_incarnation: (entered != 0).then_some(entered),
            facts,
            first_status: get32(bytes, 88) as i32,
            post_status: get32(bytes, 92) as i32,
            cohort,
        };
        report.validate()?;
        Ok(report)
    }
}
