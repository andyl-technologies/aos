//! Defines canonical observations for the proposed publisher subscription region.
//!
//! ```text
//! region[4096] = header[256] | publication[1536] | receiver[512] |
//!                terminal[512] | zero[1280]
//! header: CRUCPLM1 | schema:u32 | bytes:u32 | lender:u64 | flags:u64 |
//!         account:u64 | process:u64 | capability[32] | reservation[32] |
//!         node:u32 | nodes:u32 | three offset/length pairs | zero[112]
//! ticket:u64 = recipient_serial << 3 | phase
//! ```
//!
//! Integers use big-endian encoding. These pure codecs operate on stable,
//! caller-owned bytes; they perform no mapped atomic access, descriptor import,
//! subscription birth, or physical return. The proposal remains unavailable
//! until the paired producer, receiver, and their actual custody are integrated.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod records;
mod purpose;
mod setup;

pub mod quantum;

use crate::boundary_action::{ACTION_BYTES, ActionObservation};

pub use records::{PublisherLoanIdentity, PublisherOutcome, PublisherReturn, PublisherTerminal};
pub use purpose::{PUBLISHER_PURPOSE_BYTES, PublisherPurpose};
pub use setup::{PUBLISHER_SETUP_FRAME_BYTES, PublisherSetup};
#[cfg(unix)]
pub use setup::send_publisher_setup_frame_with_descriptors;

/// Requested file extent of the proposed subscription region.
pub const PUBLISHER_REGION_BYTES: usize = 4096;

/// Immutable header extent, excluding mutable publications.
pub const PUBLISHER_HEADER_BYTES: usize = 256;

/// Fixed immutable scheduler command extent.
pub const PUBLISHER_COMMAND_BYTES: usize = 128;

/// Fixed publication extent, including its sequence word.
pub const PUBLISHER_PUBLICATION_BYTES: usize = 1536;

/// Receiver return extent, excluding the preceding atomic ticket word.
pub const PUBLISHER_RETURN_BYTES: usize = 504;

/// Producer terminal extent, including its sequence word.
pub const PUBLISHER_TERMINAL_BYTES: usize = 512;

/// Largest recipient ticket serial that fits beside its three-bit phase.
pub const PUBLISHER_TICKET_MAX_SERIAL: u64 = (1 << 61) - 1;

const SPANS: [(usize, u32); 6] = [
    (120, 256),
    (124, 1536),
    (128, 1792),
    (132, 512),
    (136, 2304),
    (140, 512),
];

/// Refuses noncanonical publisher subscription observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid publisher subscription observation")]
pub struct PublisherDecodeError;

/// Describes immutable region identity without authenticating its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherHeader {
    /// Nonzero, nonexhausted generation of the actual retained lender.
    pub lender_generation: u64,
    /// Actual containing account incarnation.
    pub account_generation: u64,
    /// Actual Source process incarnation.
    pub process_generation: u64,
    /// Containing Source capability identity.
    pub capability: [u8; 32],
    /// Actual Source reservation identity.
    pub reservation: [u8; 32],
    /// Node index within the retained setup roster.
    pub node_index: u32,
    /// Number of nodes in that roster.
    pub node_count: u32,
}

impl PublisherHeader {
    fn validate(&self) -> Result<(), PublisherDecodeError> {
        if !generation(self.lender_generation)
            || !generation(self.account_generation)
            || !generation(self.process_generation)
            || self.capability == [0; 32]
            || self.reservation == [0; 32]
            || !(1..=32).contains(&self.node_count)
            || self.node_index >= self.node_count
        {
            return Err(PublisherDecodeError);
        }

        Ok(())
    }

    /// Encodes the exact immutable header with canonical disjoint spans.
    ///
    /// # Errors
    /// Refuses missing or exhausted identities and invalid node coordinates.
    pub fn encode(&self) -> Result<[u8; PUBLISHER_HEADER_BYTES], PublisherDecodeError> {
        self.validate()?;

        let mut bytes = [0; PUBLISHER_HEADER_BYTES];
        bytes[..8].copy_from_slice(b"CRUCPLM1");
        put32(&mut bytes, 8, 1);
        put32(&mut bytes, 12, PUBLISHER_REGION_BYTES as u32);
        put64(&mut bytes, 16, self.lender_generation);
        put64(&mut bytes, 32, self.account_generation);
        put64(&mut bytes, 40, self.process_generation);
        bytes[48..80].copy_from_slice(&self.capability);
        bytes[80..112].copy_from_slice(&self.reservation);
        put32(&mut bytes, 112, self.node_index);
        put32(&mut bytes, 116, self.node_count);
        for (offset, value) in SPANS {
            put32(&mut bytes, offset, value);
        }

        Ok(bytes)
    }

    /// Decodes one exact immutable header before any ownership effects.
    ///
    /// # Errors
    /// Refuses short or trailing data, unknown editions or flags, altered span
    /// geometry, nonzero padding, invalid identities, or invalid node coordinates.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_HEADER_BYTES
            || bytes[..8] != *b"CRUCPLM1"
            || get32(bytes, 8) != 1
            || get32(bytes, 12) != PUBLISHER_REGION_BYTES as u32
            || get64(bytes, 24) != 0
            || bytes[144..].iter().any(|byte| *byte != 0)
            || SPANS
                .into_iter()
                .any(|(offset, value)| get32(bytes, offset) != value)
        {
            return Err(PublisherDecodeError);
        }

        let header = Self {
            lender_generation: get64(bytes, 16),
            account_generation: get64(bytes, 32),
            process_generation: get64(bytes, 40),
            capability: array_at(bytes, 48),
            reservation: array_at(bytes, 80),
            node_index: get32(bytes, 112),
            node_count: get32(bytes, 116),
        };
        header.validate()?;

        Ok(header)
    }
}

/// Distinguishes retired-ceiling and authenticated next-idle completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublisherStopMode {
    /// Requires the actual retired ceiling witness.
    RetiredCeiling,
    /// Also permits the named command's actual next-idle witness.
    NextIdle {
        /// Nonzero, nonexhausted generation of that next-idle target.
        target_generation: u64,
    },
}

/// Corroborates an immutable scheduler command under its actual paid owner.
///
/// Raw instruction counts, logical ticks, and native nanoseconds are distinct
/// domains. This record neither converts them nor creates a Quantum Original.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherCommand {
    /// Nonzero even generation of the genuine scheduler publication.
    pub scheduler_generation: u64,
    /// Actual raw instruction count at command entry.
    pub initial_raw_icount: u64,
    /// Absolute raw instruction ceiling, at least the initial count.
    pub maximum_raw_icount: u64,
    /// Effective absolute ceiling in the logical-tick domain.
    pub logical_tick_ceiling: u64,
    /// Effective absolute ceiling in native monotonic nanoseconds.
    pub native_monotonic_ns_ceiling: u64,
    /// Actual completion mode, independently of any slot's numeric tags.
    pub stop: PublisherStopMode,
    /// Immutable command frontier to match against the containing cohort.
    pub frontier: u64,
}

impl PublisherCommand {
    fn validate(&self) -> Result<(), PublisherDecodeError> {
        if !sequence(self.scheduler_generation)
            || self.maximum_raw_icount < self.initial_raw_icount
            || matches!(self.stop, PublisherStopMode::NextIdle { target_generation }
                if !generation(target_generation))
        {
            return Err(PublisherDecodeError);
        }

        Ok(())
    }

    /// Encodes one immutable command, keeping all outcome bytes absent.
    ///
    /// # Errors
    /// Refuses invalid scheduler or next-idle generations and a raw ceiling
    /// below the initial instruction count.
    pub fn encode(self) -> Result<[u8; PUBLISHER_COMMAND_BYTES], PublisherDecodeError> {
        self.validate()?;

        let mut bytes = [0; PUBLISHER_COMMAND_BYTES];
        bytes[..8].copy_from_slice(b"CRUCQCM1");
        put32(&mut bytes, 8, 1);
        put32(&mut bytes, 12, PUBLISHER_COMMAND_BYTES as u32);
        put64(&mut bytes, 16, self.scheduler_generation);
        put64(&mut bytes, 24, self.initial_raw_icount);
        put64(&mut bytes, 32, self.maximum_raw_icount);
        put64(&mut bytes, 40, self.logical_tick_ceiling);
        put64(&mut bytes, 48, self.native_monotonic_ns_ceiling);
        let (mode, target) = match self.stop {
            PublisherStopMode::RetiredCeiling => (1, 0),
            PublisherStopMode::NextIdle { target_generation } => (2, target_generation),
        };
        put32(&mut bytes, 56, mode);
        put64(&mut bytes, 64, self.frontier);
        put64(&mut bytes, 72, target);

        Ok(bytes)
    }

    /// Decodes one exact command without interpreting it as admission.
    ///
    /// # Errors
    /// Refuses altered geometry, magic or schema, nonzero reserved bytes,
    /// unknown stop modes, invalid generations, or a decreasing raw ceiling.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_COMMAND_BYTES
            || bytes[..8] != *b"CRUCQCM1"
            || get32(bytes, 8) != 1
            || get32(bytes, 12) != PUBLISHER_COMMAND_BYTES as u32
            || get32(bytes, 60) != 0
            || bytes[80..].iter().any(|byte| *byte != 0)
        {
            return Err(PublisherDecodeError);
        }

        let target = get64(bytes, 72);
        let stop = match (get32(bytes, 56), target) {
            (1, 0) => PublisherStopMode::RetiredCeiling,
            (2, target_generation) if generation(target_generation) => {
                PublisherStopMode::NextIdle { target_generation }
            }
            _ => return Err(PublisherDecodeError),
        };
        let command = Self {
            scheduler_generation: get64(bytes, 16),
            initial_raw_icount: get64(bytes, 24),
            maximum_raw_icount: get64(bytes, 32),
            logical_tick_ceiling: get64(bytes, 40),
            native_monotonic_ns_ceiling: get64(bytes, 48),
            stop,
            frontier: get64(bytes, 64),
        };
        command.validate()?;

        Ok(command)
    }
}

/// Describes producer permission separately from retained physical debt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PublisherPermission {
    /// Permits admission only through the actual retained operation owner.
    Borrowable = 1,
    /// Refuses further semantic effects while retaining physical obligations.
    Revoked = 2,
    /// Describes terminal producer permission without certifying consumption.
    Terminal = 3,
}

/// Corroborates one retained cohort and its optional immutable Quantum command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherPublication {
    /// Stable nonzero even publication sequence.
    pub sequence: u64,
    /// Actual producer offer incarnation, independently of the ticket serial.
    pub offer_generation: u64,
    /// Actual recipient-specific borrower serial.
    pub ticket_serial: u64,
    /// Observed permission, independent of physical membership retention.
    pub permission: PublisherPermission,
    /// Stable standing publication bound to this cohort.
    pub standing_sequence: u64,
    /// Existing canonical action observation with distinct born/projected masks.
    pub cohort: ActionObservation,
    /// Immutable command, present exactly for a class-1 first primary row.
    pub command: Option<PublisherCommand>,
}

impl PublisherPublication {
    fn validate(&self) -> Result<(), PublisherDecodeError> {
        if !sequence(self.sequence)
            || !generation(self.offer_generation)
            || !(1..=PUBLISHER_TICKET_MAX_SERIAL).contains(&self.ticket_serial)
            || !sequence(self.standing_sequence)
            || self.cohort.binding.park_request.is_some()
            || self.cohort.binding.loan_sequence > self.standing_sequence
        {
            return Err(PublisherDecodeError);
        }

        match self.command {
            Some(command) => {
                command.validate()?;
                if self.cohort.primary_count != 1
                    || self.cohort.parents[0].class != 1
                    || command.frontier != self.cohort.binding.frontier
                {
                    return Err(PublisherDecodeError);
                }
            }
            None if self.cohort.parents[0].class == 1 => return Err(PublisherDecodeError),
            None => {}
        }

        Ok(())
    }

    /// Encodes a canonical publication without lending any memberships.
    ///
    /// # Errors
    /// Refuses invalid identities, sequences, cohort syntax, command class or
    /// frontier correlation, including Park observations in this action region.
    pub fn encode(&self) -> Result<[u8; PUBLISHER_PUBLICATION_BYTES], PublisherDecodeError> {
        self.validate()?;
        let cohort = self.cohort.encode().map_err(|_| PublisherDecodeError)?;

        let mut bytes = [0; PUBLISHER_PUBLICATION_BYTES];
        put64(&mut bytes, 0, self.sequence);
        put64(&mut bytes, 8, self.offer_generation);
        put64(&mut bytes, 16, self.ticket_serial);
        put64(&mut bytes, 24, self.permission as u64);
        put64(&mut bytes, 32, self.standing_sequence);
        put64(&mut bytes, 40, u64::from(self.command.is_some()));
        put32(&mut bytes, 48, 128);
        put32(&mut bytes, 52, ACTION_BYTES as u32);
        put32(&mut bytes, 56, 1024);
        put32(&mut bytes, 60, if self.command.is_some() { 128 } else { 0 });
        bytes[128..1024].copy_from_slice(&cohort);
        if let Some(command) = self.command {
            bytes[1024..1152].copy_from_slice(&command.encode()?);
        }

        Ok(bytes)
    }

    /// Decodes a stable copied publication with exact bounded geometry.
    ///
    /// # Errors
    /// Refuses malformed identities, unknown tags, changed geometry, padding,
    /// noncanonical cohorts, or inconsistent command class/frontier metadata.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_PUBLICATION_BYTES
            || get32(bytes, 48) != 128
            || get32(bytes, 52) != ACTION_BYTES as u32
            || get32(bytes, 56) != 1024
            || bytes[64..128].iter().any(|byte| *byte != 0)
            || bytes[1152..].iter().any(|byte| *byte != 0)
            || bytes[128..136] != *b"CRUCACT2"
        {
            return Err(PublisherDecodeError);
        }

        let permission = match get64(bytes, 24) {
            1 => PublisherPermission::Borrowable,
            2 => PublisherPermission::Revoked,
            3 => PublisherPermission::Terminal,
            _ => return Err(PublisherDecodeError),
        };
        let command = match (get64(bytes, 40), get32(bytes, 60)) {
            (0, 0) if bytes[1024..1152].iter().all(|byte| *byte == 0) => None,
            (1, 128) => Some(PublisherCommand::decode(&bytes[1024..1152])?),
            _ => return Err(PublisherDecodeError),
        };
        let publication = Self {
            sequence: get64(bytes, 0),
            offer_generation: get64(bytes, 8),
            ticket_serial: get64(bytes, 16),
            permission,
            standing_sequence: get64(bytes, 32),
            cohort: ActionObservation::decode(&bytes[128..1024])
                .map_err(|_| PublisherDecodeError)?,
            command,
        };
        publication.validate()?;

        Ok(publication)
    }
}

/// Identifies one factual ticket phase, independently of actual custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PublisherTicketPhase {
    /// Producer has retained a fresh recipient-specific borrower.
    Issued = 1,
    /// Receiver has acquired that exact issued borrower.
    Acquired = 2,
    /// Receiver has joined work children and published its return record.
    ReturnRequested = 3,
    /// Producer has physically consumed its memberships and command borrower.
    Consumed = 4,
    /// Receiver has completed its independent post and local tail returns.
    Closed = 5,
    /// Producer won withdrawal before receiver acquisition.
    Withdrawn = 6,
}

/// Carries ticket syntax without performing an ownership transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherTicket {
    /// Nonzero, nonwrapping serial of the actual recipient-specific borrower.
    pub serial: u64,
    /// Observed phase; matching bytes alone do not establish its physical facts.
    pub phase: PublisherTicketPhase,
}

impl PublisherTicket {
    /// Packs one serial and phase into its canonical public word.
    ///
    /// # Errors
    /// Refuses zero or serials exceeding the available sixty-one bits.
    pub fn encode(self) -> Result<u64, PublisherDecodeError> {
        if !(1..=PUBLISHER_TICKET_MAX_SERIAL).contains(&self.serial) {
            return Err(PublisherDecodeError);
        }

        Ok((self.serial << 3) | self.phase as u64)
    }

    /// Decodes one word without acquiring, withdrawing, or closing a loan.
    ///
    /// # Errors
    /// Refuses zero serials and the reserved phases zero and seven.
    pub fn decode(word: u64) -> Result<Self, PublisherDecodeError> {
        let phase = match word & 7 {
            1 => PublisherTicketPhase::Issued,
            2 => PublisherTicketPhase::Acquired,
            3 => PublisherTicketPhase::ReturnRequested,
            4 => PublisherTicketPhase::Consumed,
            5 => PublisherTicketPhase::Closed,
            6 => PublisherTicketPhase::Withdrawn,
            _ => return Err(PublisherDecodeError),
        };
        let serial = word >> 3;
        if serial == 0 {
            return Err(PublisherDecodeError);
        }

        Ok(Self { serial, phase })
    }
}

fn generation(value: u64) -> bool {
    value != 0 && value != u64::MAX
}

fn sequence(value: u64) -> bool {
    generation(value) && value & 1 == 0
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&bytes[offset..offset + N]);
    value
}

fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(array_at(bytes, offset))
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(array_at(bytes, offset))
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests;
