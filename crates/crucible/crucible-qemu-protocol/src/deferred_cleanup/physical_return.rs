//! Records entered-owner, reservation and funding returns independently.
//!
//! ```text
//! return[128] = CRUCDRT1 | schema=1 | bytes=128 | sequence[8] |
//!               reservation[40] | request/entry/return incarnations[24] |
//!               kind/facts/first/post[16] | zero[24]
//! ```
//!
//! Known consumption survives an interrupted return capture or a negative post.
//! A zero request or entry for a parent return does not establish no-entry.
//! Decoding never invokes a destructor or authorizes parent retirement.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    DeferredCleanupCapability, DeferredCleanupDecodeError, DeferredCleanupIdentity, generation,
    get32, get64, header, identity, put32, put64, sequence, write_header,
};

/// Fixed extent of each separately retained physical-return observation.
pub const DEFERRED_CLEANUP_RETURN_BYTES: usize = 128;

/// Selects the actual owner described by one external return journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DeferredCleanupReturnKind {
    /// The actual entered Cleanup operation owner.
    EnteredOwner = 1,
    /// The retained dormant reservation, after actual borrower closure.
    Reservation = 2,
    /// The same-parent physical funding child, after actual physical return.
    Funding = 3,
}

impl DeferredCleanupReturnKind {
    fn decode(value: u32) -> Result<Self, DeferredCleanupDecodeError> {
        match value {
            1 => Ok(Self::EnteredOwner),
            2 => Ok(Self::Reservation),
            3 => Ok(Self::Funding),
            _ => Err(DeferredCleanupDecodeError),
        }
    }
}

/// Preserves actual consumption separately from first and post observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredCleanupReturnFacts {
    /// The actual destructor or physical return was attempted.
    pub attempted: bool,
    /// Its signed first status was captured.
    pub returned: bool,
    /// The actual owner was consumed, even if later capture or post failed.
    pub consumed: bool,
    /// An independent post observation was attempted.
    pub post_attempted: bool,
    /// Its signed status was captured.
    pub post_returned: bool,
    /// Unknown facts continue to retain debt.
    pub uncertain: bool,
}

impl DeferredCleanupReturnFacts {
    fn bits(self) -> u32 {
        u32::from(self.attempted)
            | u32::from(self.returned) << 1
            | u32::from(self.consumed) << 2
            | u32::from(self.post_attempted) << 3
            | u32::from(self.post_returned) << 4
            | u32::from(self.uncertain) << 5
    }

    fn decode(bits: u32) -> Result<Self, DeferredCleanupDecodeError> {
        if bits & !63 != 0 {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(Self {
            attempted: bits & 1 != 0,
            returned: bits & 2 != 0,
            consumed: bits & 4 != 0,
            post_attempted: bits & 8 != 0,
            post_returned: bits & 16 != 0,
            uncertain: bits & 32 != 0,
        })
    }
}

/// Describes one actual external physical-return history without granting credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredCleanupReturn {
    /// Positive even publication sequence of this return record.
    pub sequence: u64,
    /// Exact dormant reservation whose owner chain is being returned.
    pub reservation: DeferredCleanupIdentity,
    /// Existing request sequence; absence is allowed for a parent return.
    pub request_sequence: Option<u64>,
    /// Actual entered incarnation; absence is allowed for a parent return.
    pub entered_incarnation: Option<u64>,
    /// Existing nonwrapping external return-journal incarnation.
    pub return_incarnation: u64,
    /// Independent owner whose actual disposition this journal records.
    pub kind: DeferredCleanupReturnKind,
    /// Factual attempt, consumption and post history.
    pub facts: DeferredCleanupReturnFacts,
    /// Nonpositive captured first status, zero when not captured.
    pub first_status: i32,
    /// Nonpositive captured post status, zero when not captured.
    pub post_status: i32,
}

impl DeferredCleanupReturn {
    fn validate(&self) -> Result<(), DeferredCleanupDecodeError> {
        self.reservation.validate()?;
        if !sequence(self.sequence)
            || !generation(self.return_incarnation)
            || self.request_sequence.is_some_and(|value| !sequence(value))
            || self
                .entered_incarnation
                .is_some_and(|value| !generation(value))
            || (self.kind == DeferredCleanupReturnKind::EnteredOwner
                && (self.request_sequence.is_none() || self.entered_incarnation.is_none()))
            || !self.facts.attempted
            || (self.facts.post_returned && !self.facts.post_attempted)
            || (!self.facts.returned && self.first_status != 0)
            || (!self.facts.post_returned && self.post_status != 0)
            || self.first_status > 0
            || self.post_status > 0
        {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(())
    }

    /// Checks reservation correlation without proving actual parent closure.
    ///
    /// # Errors
    /// Refuses invalid records or a different reservation identity/incarnation.
    pub fn validate_for(
        &self,
        capability: &DeferredCleanupCapability,
    ) -> Result<(), DeferredCleanupDecodeError> {
        self.validate()?;
        capability.validate()?;
        if self.reservation != capability.reservation {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(())
    }

    /// Encodes actual consumption independently of capture and post success.
    ///
    /// # Errors
    /// Refuses invalid identities, missing entered-owner correlation,
    /// inconsistent status facts or positive statuses.
    pub fn encode(
        &self,
    ) -> Result<[u8; DEFERRED_CLEANUP_RETURN_BYTES], DeferredCleanupDecodeError> {
        self.validate()?;
        let mut bytes = [0; DEFERRED_CLEANUP_RETURN_BYTES];
        write_header(&mut bytes, b"CRUCDRT1");
        put64(&mut bytes, 16, self.sequence);
        bytes[24..56].copy_from_slice(&self.reservation.identity);
        put64(&mut bytes, 56, self.reservation.incarnation);
        put64(&mut bytes, 64, self.request_sequence.unwrap_or(0));
        put64(&mut bytes, 72, self.entered_incarnation.unwrap_or(0));
        put64(&mut bytes, 80, self.return_incarnation);
        put32(&mut bytes, 88, self.kind as u32);
        put32(&mut bytes, 92, self.facts.bits());
        put32(&mut bytes, 96, self.first_status as u32);
        put32(&mut bytes, 100, self.post_status as u32);
        Ok(bytes)
    }

    /// Decodes one physical-return record without retrying consumed owners.
    ///
    /// # Errors
    /// Refuses invalid framing, padding, identities, kind, status facts or
    /// entered-owner association. Missing parent-entry fields grant no no-entry proof.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeferredCleanupDecodeError> {
        header(bytes, b"CRUCDRT1", DEFERRED_CLEANUP_RETURN_BYTES)?;
        if bytes[104..].iter().any(|value| *value != 0) {
            return Err(DeferredCleanupDecodeError);
        }
        let request = get64(bytes, 64);
        let entered = get64(bytes, 72);
        let report = Self {
            sequence: get64(bytes, 16),
            reservation: identity(bytes, 24),
            request_sequence: (request != 0).then_some(request),
            entered_incarnation: (entered != 0).then_some(entered),
            return_incarnation: get64(bytes, 80),
            kind: DeferredCleanupReturnKind::decode(get32(bytes, 88))?,
            facts: DeferredCleanupReturnFacts::decode(get32(bytes, 92))?,
            first_status: get32(bytes, 96) as i32,
            post_status: get32(bytes, 100) as i32,
        };
        report.validate()?;
        Ok(report)
    }
}
