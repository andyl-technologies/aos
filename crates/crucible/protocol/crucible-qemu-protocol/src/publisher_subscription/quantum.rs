//! Defines the separate schema-two Quantum and terminal-cleanup observations.
//!
//! ```text
//! header[256]: CRUCPLM2 | schema=2 | existing immutable identity and spans
//! publication[1536]: identities[64] | role_map[48] | zero[16] |
//!                    cohort[896] | command[128] | zero[384]
//! role_map: edition:u32 | work_row=0:u32 | cleanup_row=1:u32 |
//!           work_mask:u32 | cleanup_mask:u32 | flags=0:u32 |
//!           cleanup_permission:u64 | cleanup_loan:u64 | cleanup_entry:u64
//! ```
//!
//! These pure codecs describe two independently retained operation loans. They
//! create neither loan, a finite cleanup interval, resource credit nor physical
//! return. Schema-one codecs and active setup negotiation remain unchanged.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    PUBLISHER_HEADER_BYTES, PUBLISHER_PUBLICATION_BYTES, PUBLISHER_TICKET_MAX_SERIAL,
    PublisherCommand, PublisherDecodeError, PublisherHeader, PublisherPermission, generation,
    get32, get64, put32, put64, sequence,
};
use crate::boundary_action::{ACTION_BYTES, ActionObservation};

mod records;
pub use records::{QuantumPublisherReturn, QuantumPublisherTerminal};

mod negotiation;
pub use negotiation::{QuantumPublisherPurpose, QuantumPublisherSetup};
#[cfg(unix)]
pub use negotiation::send_quantum_publisher_setup_frame_with_descriptors;

mod stacks;
#[cfg(unix)]
pub use stacks::send_quantum_stack_setup_frame_with_descriptors;
pub use stacks::{
    QUANTUM_STACK_PURPOSE_BYTES, QuantumStackPublisherSetup, QuantumStackPurpose,
    QuantumStackReservation,
};

/// Describes an explicitly negotiated schema-two Quantum region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantumPublisherHeader {
    /// Immutable lender, account, process and node identity.
    pub identity: PublisherHeader,
}

impl QuantumPublisherHeader {
    /// Encodes the schema-two identity and canonical unchanged region spans.
    ///
    /// # Errors
    /// Refuses invalid lender, account, process or node identity.
    pub fn encode(self) -> Result<[u8; PUBLISHER_HEADER_BYTES], PublisherDecodeError> {
        let mut bytes = self.identity.encode()?;
        bytes[..8].copy_from_slice(b"CRUCPLM2");
        put32(&mut bytes, 8, 2);
        Ok(bytes)
    }

    /// Decodes exactly schema two without accepting a schema-one header.
    ///
    /// # Errors
    /// Refuses other editions, malformed identity, flags, spans or padding.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_HEADER_BYTES
            || bytes[..8] != *b"CRUCPLM2"
            || get32(bytes, 8) != 2
        {
            return Err(PublisherDecodeError);
        }

        // Only the edition differs; reuse the exact shared identity validator
        // after establishing this edition, without a legacy decoding fallback.
        let mut identity = [0; PUBLISHER_HEADER_BYTES];
        identity.copy_from_slice(bytes);
        identity[..8].copy_from_slice(b"CRUCPLM1");
        put32(&mut identity, 8, 1);
        Ok(Self {
            identity: PublisherHeader::decode(&identity)?,
        })
    }
}

/// Correlates the distinct work and independently entered Cleanup loans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantumPublisherRoleMap {
    /// Work primary bit and its actual Preparation dependency, if present.
    pub work_mask: u32,
    /// Cleanup primary bit and its actual Preparation dependency, if present.
    pub cleanup_mask: u32,
    /// Independent Cleanup permission, which work revocation cannot replace.
    pub cleanup_permission: PublisherPermission,
    /// Actual recipient-specific Cleanup loan incarnation.
    pub cleanup_loan_generation: u64,
    /// Actual already-entered Cleanup operation incarnation.
    pub cleanup_entry_incarnation: u64,
}

impl QuantumPublisherRoleMap {
    fn validate(self, cohort: &ActionObservation) -> Result<(), PublisherDecodeError> {
        cohort.encode().map_err(|_| PublisherDecodeError)?;
        if cohort.primary_count != 2
            || !(2..=4).contains(&cohort.row_count)
            || !cohort.cohort_current
            || cohort.borrowed_mask != (1 << cohort.row_count) - 1
            || cohort.projected_mask != cohort.borrowed_mask
            || cohort.parents[0].class != 1
            || cohort.parents[0].required != 1
            || cohort.parents[0].completed != 0
            || cohort.parents[1].class != 13
            || (cohort.parents[0].cap == cohort.parents[1].cap
                && cohort.parents[0].budget_owner == cohort.parents[1].budget_owner
                && cohort.parents[0].operation == cohort.parents[1].operation)
            || !generation(self.cleanup_loan_generation)
            || !generation(self.cleanup_entry_incarnation)
        {
            return Err(PublisherDecodeError);
        }

        let constraint_mask = |index: usize| {
            let preparation = cohort.parents[index].preparation;
            (1 << index)
                | if preparation == 0 {
                    0
                } else {
                    1 << (preparation - 1)
                }
        };
        if self.work_mask != constraint_mask(0)
            || self.cleanup_mask != constraint_mask(1)
            || self.work_mask | self.cleanup_mask != cohort.borrowed_mask
        {
            return Err(PublisherDecodeError);
        }
        Ok(())
    }
}

/// Describes one immutable Quantum command with independent terminal permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantumPublisherPublication {
    /// Original stable nonzero even command publication sequence.
    pub sequence: u64,
    /// Actual producer offer incarnation.
    pub offer_generation: u64,
    /// Actual recipient-specific ticket serial.
    pub ticket_serial: u64,
    /// Work permission, independently of Cleanup permission and physical debt.
    pub work_permission: PublisherPermission,
    /// Stable standing publication bound to the original cohort.
    pub standing_sequence: u64,
    /// Original full cohort containing both primaries and their dependencies.
    pub cohort: ActionObservation,
    /// Immutable scheduler command; non-Quantum offers are outside this codec.
    pub command: PublisherCommand,
    /// Canonical role and independent Cleanup identity observations.
    pub roles: QuantumPublisherRoleMap,
}

impl QuantumPublisherPublication {
    fn validate(&self) -> Result<(), PublisherDecodeError> {
        self.command.validate()?;
        self.roles.validate(&self.cohort)?;
        if !sequence(self.sequence)
            || !generation(self.offer_generation)
            || !(1..=PUBLISHER_TICKET_MAX_SERIAL).contains(&self.ticket_serial)
            || !sequence(self.standing_sequence)
            || self.cohort.binding.park_request.is_some()
            || self.cohort.binding.loan_sequence > self.standing_sequence
            || self.command.frontier != self.cohort.binding.frontier
        {
            return Err(PublisherDecodeError);
        }
        Ok(())
    }

    /// Encodes the exact command and both role observations without issuing them.
    ///
    /// # Errors
    /// Refuses malformed identity, clocks, class/dependency roles, partial
    /// cohorts, inconsistent masks or missing/exhausted Cleanup incarnations.
    pub fn encode(&self) -> Result<[u8; PUBLISHER_PUBLICATION_BYTES], PublisherDecodeError> {
        self.validate()?;
        let mut bytes = [0; PUBLISHER_PUBLICATION_BYTES];
        put64(&mut bytes, 0, self.sequence);
        put64(&mut bytes, 8, self.offer_generation);
        put64(&mut bytes, 16, self.ticket_serial);
        put64(&mut bytes, 24, self.work_permission as u64);
        put64(&mut bytes, 32, self.standing_sequence);
        put64(&mut bytes, 40, 1);
        put32(&mut bytes, 48, 128);
        put32(&mut bytes, 52, ACTION_BYTES as u32);
        put32(&mut bytes, 56, 1024);
        put32(&mut bytes, 60, 128);
        put32(&mut bytes, 64, 1);
        put32(&mut bytes, 68, 0);
        put32(&mut bytes, 72, 1);
        put32(&mut bytes, 76, self.roles.work_mask);
        put32(&mut bytes, 80, self.roles.cleanup_mask);
        put64(&mut bytes, 88, self.roles.cleanup_permission as u64);
        put64(&mut bytes, 96, self.roles.cleanup_loan_generation);
        put64(&mut bytes, 104, self.roles.cleanup_entry_incarnation);
        bytes[128..1024].copy_from_slice(&self.cohort.encode().map_err(|_| PublisherDecodeError)?);
        bytes[1024..1152].copy_from_slice(&self.command.encode()?);
        Ok(bytes)
    }

    /// Decodes only the paired schema-two Quantum publication syntax.
    ///
    /// # Errors
    /// Refuses other roles/editions, unknown permissions, altered geometry,
    /// padding, incomplete cohorts, or invalid operation/command correlations.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_PUBLICATION_BYTES
            || get64(bytes, 40) != 1
            || get32(bytes, 48) != 128
            || get32(bytes, 52) != ACTION_BYTES as u32
            || get32(bytes, 56) != 1024
            || get32(bytes, 60) != 128
            || get32(bytes, 64) != 1
            || get32(bytes, 68) != 0
            || get32(bytes, 72) != 1
            || get32(bytes, 84) != 0
            || bytes[112..128].iter().any(|byte| *byte != 0)
            || bytes[1152..].iter().any(|byte| *byte != 0)
            || bytes[128..136] != *b"CRUCACT2"
        {
            return Err(PublisherDecodeError);
        }

        let publication = Self {
            sequence: get64(bytes, 0),
            offer_generation: get64(bytes, 8),
            ticket_serial: get64(bytes, 16),
            work_permission: permission(get64(bytes, 24))?,
            standing_sequence: get64(bytes, 32),
            cohort: ActionObservation::decode(&bytes[128..1024])
                .map_err(|_| PublisherDecodeError)?,
            command: PublisherCommand::decode(&bytes[1024..1152])?,
            roles: QuantumPublisherRoleMap {
                work_mask: get32(bytes, 76),
                cleanup_mask: get32(bytes, 80),
                cleanup_permission: permission(get64(bytes, 88))?,
                cleanup_loan_generation: get64(bytes, 96),
                cleanup_entry_incarnation: get64(bytes, 104),
            },
        };
        publication.validate()?;
        Ok(publication)
    }

    /// Checks an observation-only monotonic permission update of one command.
    ///
    /// This does not perform atomic access, authenticate a producer or grant
    /// permission. Every field other than the two permission words must match.
    ///
    /// # Errors
    /// Refuses changed identities/clocks/roles, invalid publications or any
    /// restoration of either work or Cleanup permission.
    pub fn validate_permission_update(&self, previous: &Self) -> Result<(), PublisherDecodeError> {
        self.validate()?;
        previous.validate()?;
        let mut expected = *previous;
        expected.work_permission = self.work_permission;
        expected.roles.cleanup_permission = self.roles.cleanup_permission;
        if expected != *self
            || (self.work_permission as u8) < previous.work_permission as u8
            || (self.roles.cleanup_permission as u8) < previous.roles.cleanup_permission as u8
        {
            return Err(PublisherDecodeError);
        }
        Ok(())
    }
}

fn permission(word: u64) -> Result<PublisherPermission, PublisherDecodeError> {
    match word {
        1 => Ok(PublisherPermission::Borrowable),
        2 => Ok(PublisherPermission::Revoked),
        3 => Ok(PublisherPermission::Terminal),
        _ => Err(PublisherDecodeError),
    }
}

#[cfg(test)]
mod tests;
