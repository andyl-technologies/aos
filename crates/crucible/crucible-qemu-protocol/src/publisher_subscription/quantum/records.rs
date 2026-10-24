//! Correlates schema-two physical journals with both original role loans.
//!
//! ```text
//! return[504]: common[88] | work_mask:u32 | cleanup_mask:u32 |
//!              cleanup_loan:u64 | cleanup_entry:u64 | terminal_serial:u64 | zero[384]
//! terminal[512]: common[64] | work_mask:u32 | cleanup_mask:u32 |
//!                cleanup_loan:u64 | cleanup_entry:u64 | terminal_serial:u64 | zero[416]
//! ```
//!
//! These records preserve partial and consumed-negative facts. Their decoded
//! masks and identities cannot certify an actual destructor or ticket transition.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::super::{
    PUBLISHER_RETURN_BYTES, PUBLISHER_TERMINAL_BYTES, PublisherDecodeError, PublisherLoanIdentity,
    PublisherReturn, PublisherTerminal, generation, get32, get64, put32, put64,
};
use super::QuantumPublisherPublication;

/// Preserves separate receiver row-view returns for the two retained roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantumPublisherReturn {
    /// Existing receiver correlation, statuses, outcome and aggregate facts.
    pub common: PublisherReturn,
    /// Actually returned Work views, including its Preparation if present.
    pub returned_work_mask: u32,
    /// Actually returned Cleanup views, including its Preparation if present.
    pub returned_cleanup_mask: u32,
    /// Original recipient-specific Cleanup loan incarnation.
    pub cleanup_loan_generation: u64,
    /// Original entered Cleanup operation incarnation.
    pub cleanup_entry_incarnation: u64,
    /// Actual nonwrapping receiver terminal-return journal incarnation.
    pub terminal_return_serial: u64,
}

impl QuantumPublisherReturn {
    fn validate(
        &self,
        publication: &QuantumPublisherPublication,
    ) -> Result<(), PublisherDecodeError> {
        publication.validate()?;
        self.common.encode()?;
        let expected = PublisherLoanIdentity {
            ticket_serial: publication.ticket_serial,
            offer_generation: publication.offer_generation,
            command_sequence: publication.sequence,
        };
        if self.common.loan != expected
            || self.returned_work_mask & !publication.roles.work_mask != 0
            || self.returned_cleanup_mask & !publication.roles.cleanup_mask != 0
            || self.returned_work_mask | self.returned_cleanup_mask
                != self.common.returned_view_mask
            || self.cleanup_loan_generation != publication.roles.cleanup_loan_generation
            || self.cleanup_entry_incarnation != publication.roles.cleanup_entry_incarnation
            || !generation(self.terminal_return_serial)
        {
            return Err(PublisherDecodeError);
        }
        Ok(())
    }

    /// Encodes actual return observations against the original publication.
    ///
    /// # Errors
    /// Refuses malformed common facts, foreign loan/entry identities, exhausted
    /// journal serials, incorrect role masks or an inconsistent aggregate mask.
    /// Partial role return and negative semantic statuses remain representable.
    pub fn encode(
        &self,
        publication: &QuantumPublisherPublication,
    ) -> Result<[u8; PUBLISHER_RETURN_BYTES], PublisherDecodeError> {
        self.validate(publication)?;
        let mut bytes = self.common.encode()?;
        put32(&mut bytes, 88, self.returned_work_mask);
        put32(&mut bytes, 92, self.returned_cleanup_mask);
        put64(&mut bytes, 96, self.cleanup_loan_generation);
        put64(&mut bytes, 104, self.cleanup_entry_incarnation);
        put64(&mut bytes, 112, self.terminal_return_serial);
        Ok(bytes)
    }

    /// Decodes bounded receiver syntax correlated to both original role loans.
    ///
    /// # Errors
    /// Refuses short/trailing data, padding, malformed or foreign identities,
    /// invalid role masks, exhausted serials or invalid common return facts.
    pub fn decode(
        bytes: &[u8],
        publication: &QuantumPublisherPublication,
    ) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_RETURN_BYTES || bytes[120..].iter().any(|byte| *byte != 0) {
            return Err(PublisherDecodeError);
        }

        let mut common = [0; PUBLISHER_RETURN_BYTES];
        common.copy_from_slice(bytes);
        common[88..].fill(0);
        let record = Self {
            common: PublisherReturn::decode(&common)?,
            returned_work_mask: get32(bytes, 88),
            returned_cleanup_mask: get32(bytes, 92),
            cleanup_loan_generation: get64(bytes, 96),
            cleanup_entry_incarnation: get64(bytes, 104),
            terminal_return_serial: get64(bytes, 112),
        };
        record.validate(publication)?;
        Ok(record)
    }
}

/// Preserves producer consumption independently for Work and Cleanup loans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantumPublisherTerminal {
    /// Existing physical consumption, exact receiver sequence and statuses.
    pub common: PublisherTerminal,
    /// Actual Work membership consumption, including its retained dependency.
    pub consumed_work_mask: u32,
    /// Actual Cleanup membership consumption, including its retained dependency.
    pub consumed_cleanup_mask: u32,
    /// Original recipient-specific Cleanup loan incarnation.
    pub cleanup_loan_generation: u64,
    /// Original entered Cleanup operation incarnation.
    pub cleanup_entry_incarnation: u64,
    /// Exact receiver terminal-return journal to which consumption belongs.
    pub terminal_return_serial: u64,
}

impl QuantumPublisherTerminal {
    fn validate(
        &self,
        publication: &QuantumPublisherPublication,
        receiver: &QuantumPublisherReturn,
    ) -> Result<(), PublisherDecodeError> {
        receiver.validate(publication)?;
        self.common.encode()?;
        if self.common.loan != receiver.common.loan
            || self.common.receiver_return_sequence != receiver.common.sequence
            || self.consumed_work_mask & !receiver.returned_work_mask != 0
            || self.consumed_cleanup_mask & !receiver.returned_cleanup_mask != 0
            || self.consumed_work_mask | self.consumed_cleanup_mask != self.common.consumed_mask
            || self.common.born_mask
                & !(publication.roles.work_mask | publication.roles.cleanup_mask)
                != 0
            || self.cleanup_loan_generation != publication.roles.cleanup_loan_generation
            || self.cleanup_entry_incarnation != publication.roles.cleanup_entry_incarnation
            || self.terminal_return_serial != receiver.terminal_return_serial
        {
            return Err(PublisherDecodeError);
        }
        Ok(())
    }

    /// Encodes physical consumption correlated to the actual receiver journal.
    ///
    /// # Errors
    /// Refuses mismatched loan/entry/journal identities, malformed common facts
    /// or consumption outside the corresponding returned role masks. Negative
    /// first/post and partial known consumption remain representable.
    pub fn encode(
        &self,
        publication: &QuantumPublisherPublication,
        receiver: &QuantumPublisherReturn,
    ) -> Result<[u8; PUBLISHER_TERMINAL_BYTES], PublisherDecodeError> {
        self.validate(publication, receiver)?;
        let mut bytes = self.common.encode()?;
        put32(&mut bytes, 64, self.consumed_work_mask);
        put32(&mut bytes, 68, self.consumed_cleanup_mask);
        put64(&mut bytes, 72, self.cleanup_loan_generation);
        put64(&mut bytes, 80, self.cleanup_entry_incarnation);
        put64(&mut bytes, 88, self.terminal_return_serial);
        Ok(bytes)
    }

    /// Decodes producer facts without querying either ended operation.
    ///
    /// # Errors
    /// Refuses short/trailing data, padding, malformed common facts, foreign
    /// identities, changed receiver correlation or invalid consumption masks.
    pub fn decode(
        bytes: &[u8],
        publication: &QuantumPublisherPublication,
        receiver: &QuantumPublisherReturn,
    ) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_TERMINAL_BYTES || bytes[96..].iter().any(|byte| *byte != 0) {
            return Err(PublisherDecodeError);
        }

        let mut common = [0; PUBLISHER_TERMINAL_BYTES];
        common.copy_from_slice(bytes);
        common[64..].fill(0);
        let record = Self {
            common: PublisherTerminal::decode(&common)?,
            consumed_work_mask: get32(bytes, 64),
            consumed_cleanup_mask: get32(bytes, 68),
            cleanup_loan_generation: get64(bytes, 72),
            cleanup_entry_incarnation: get64(bytes, 80),
            terminal_return_serial: get64(bytes, 88),
        };
        record.validate(publication, receiver)?;
        Ok(record)
    }
}
