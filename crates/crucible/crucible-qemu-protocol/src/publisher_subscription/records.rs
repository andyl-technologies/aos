//! Encodes receiver and producer physical-return observations independently.
//!
//! ```text
//! receiver[504] = sequence | ticket | offer | command | local_serial |
//!                 first:i32 | post:i32 | views:u32 | children:u32 |
//!                 outcome:u32 | units:u32 | icount | next_idle | work | zero
//! terminal[512] = sequence | ticket | offer | command | receiver_sequence |
//!                 first:i32 | post:i32 | consumed:u32 | born:u32 |
//!                 command_consumption | zero
//! ```
//!
//! All integers are big endian. Decoded masks and signed statuses preserve
//! observations, including consumed facts after a negative post. They cannot
//! certify a destructor, completed unit, or ownership-state transition.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    PUBLISHER_RETURN_BYTES, PUBLISHER_TERMINAL_BYTES, PUBLISHER_TICKET_MAX_SERIAL,
    PublisherDecodeError, generation, get32, get64, put32, put64, sequence,
};

/// Correlates terminal observations to an already retained physical loan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherLoanIdentity {
    /// Recipient-specific borrower serial, independent of the offer generation.
    pub ticket_serial: u64,
    /// Nonzero, nonexhausted producer offer incarnation.
    pub offer_generation: u64,
    /// Original stable command publication sequence.
    pub command_sequence: u64,
}

impl PublisherLoanIdentity {
    fn validate(self) -> Result<(), PublisherDecodeError> {
        if !(1..=PUBLISHER_TICKET_MAX_SERIAL).contains(&self.ticket_serial)
            || !generation(self.offer_generation)
            || !sequence(self.command_sequence)
        {
            return Err(PublisherDecodeError);
        }

        Ok(())
    }

    fn write(self, bytes: &mut [u8]) {
        put64(bytes, 8, self.ticket_serial);
        put64(bytes, 16, self.offer_generation);
        put64(bytes, 24, self.command_sequence);
    }

    fn read(bytes: &[u8]) -> Self {
        Self {
            ticket_serial: get64(bytes, 8),
            offer_generation: get64(bytes, 16),
            command_sequence: get64(bytes, 24),
        }
    }
}

/// Preserves work-unit observations without authenticating their producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublisherOutcome {
    /// Reports no observed work-unit publication.
    None,
    /// Reports one actual retired-ceiling unit, independently of first/post.
    RetiredCeiling {
        /// Nonzero, nonexhausted serial of the actual work-unit publication.
        work_unit_serial: u64,
    },
    /// Reports one actual authenticated next-idle unit.
    NextIdle {
        /// Nonzero, nonexhausted generation of that next-idle completion.
        completion_generation: u64,
        /// Nonzero, nonexhausted serial of the actual work-unit publication.
        work_unit_serial: u64,
    },
}

impl PublisherOutcome {
    fn words(self) -> Result<(u32, u32, u64, u64), PublisherDecodeError> {
        match self {
            Self::None => Ok((0, 0, 0, 0)),
            Self::RetiredCeiling { work_unit_serial } if generation(work_unit_serial) => {
                Ok((1, 1, 0, work_unit_serial))
            }
            Self::NextIdle {
                completion_generation,
                work_unit_serial,
            } if generation(completion_generation) && generation(work_unit_serial) => {
                Ok((2, 1, completion_generation, work_unit_serial))
            }
            _ => Err(PublisherDecodeError),
        }
    }

    fn read(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        match (
            get32(bytes, 56),
            get32(bytes, 60),
            get64(bytes, 72),
            get64(bytes, 80),
        ) {
            (0, 0, 0, 0) => Ok(Self::None),
            (1, 1, 0, work_unit_serial) if generation(work_unit_serial) => {
                Ok(Self::RetiredCeiling { work_unit_serial })
            }
            (2, 1, completion_generation, work_unit_serial)
                if generation(completion_generation) && generation(work_unit_serial) =>
            {
                Ok(Self::NextIdle {
                    completion_generation,
                    work_unit_serial,
                })
            }
            _ => Err(PublisherDecodeError),
        }
    }
}

/// Preserves receiver return facts separately from producer consumption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherReturn {
    /// Stable nonzero even receiver return sequence.
    pub sequence: u64,
    /// Exact already retained offer, ticket, and command correlation.
    pub loan: PublisherLoanIdentity,
    /// Nonzero, nonexhausted canonical receiver-holder serial.
    pub local_serial: u64,
    /// First semantic status, zero or negative, independent of physical return.
    pub first: i32,
    /// Independent post status, zero or negative.
    pub post: i32,
    /// Actual returned local row views, using only the low four bits.
    pub returned_view_mask: u32,
    /// Actual work-child returns, using the seven defined physical-child bits.
    pub physical_child_mask: u32,
    /// Independently retained unit observation; negative first/post may coexist.
    pub outcome: PublisherOutcome,
    /// Actual final raw instruction count, without cross-domain conversion.
    pub final_raw_icount: u64,
}

impl PublisherReturn {
    fn validate(self) -> Result<(), PublisherDecodeError> {
        self.loan.validate()?;
        self.outcome.words()?;
        if !sequence(self.sequence)
            || !generation(self.local_serial)
            || self.first > 0
            || self.post > 0
            || self.returned_view_mask & !0xf != 0
            || self.physical_child_mask & !0x7f != 0
        {
            return Err(PublisherDecodeError);
        }

        Ok(())
    }

    /// Encodes the receiver journal without declaring its actual children closed.
    ///
    /// # Errors
    /// Refuses invalid correlation, positive statuses, unknown mask bits, or
    /// inconsistent outcome generations. Partial return masks remain metadata.
    pub fn encode(self) -> Result<[u8; PUBLISHER_RETURN_BYTES], PublisherDecodeError> {
        self.validate()?;
        let (kind, units, next_idle, work) = self.outcome.words()?;

        let mut bytes = [0; PUBLISHER_RETURN_BYTES];
        put64(&mut bytes, 0, self.sequence);
        self.loan.write(&mut bytes);
        put64(&mut bytes, 32, self.local_serial);
        put32(&mut bytes, 40, self.first as u32);
        put32(&mut bytes, 44, self.post as u32);
        put32(&mut bytes, 48, self.returned_view_mask);
        put32(&mut bytes, 52, self.physical_child_mask);
        put32(&mut bytes, 56, kind);
        put32(&mut bytes, 60, units);
        put64(&mut bytes, 64, self.final_raw_icount);
        put64(&mut bytes, 72, next_idle);
        put64(&mut bytes, 80, work);

        Ok(bytes)
    }

    /// Decodes one stable copied receiver return without acknowledging it.
    ///
    /// # Errors
    /// Refuses short or trailing data, nonzero reserved bytes, invalid identity,
    /// statuses, masks, or outcome/unit correlation.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_RETURN_BYTES || bytes[88..].iter().any(|byte| *byte != 0) {
            return Err(PublisherDecodeError);
        }

        let record = Self {
            sequence: get64(bytes, 0),
            loan: PublisherLoanIdentity::read(bytes),
            local_serial: get64(bytes, 32),
            first: get32(bytes, 40) as i32,
            post: get32(bytes, 44) as i32,
            returned_view_mask: get32(bytes, 48),
            physical_child_mask: get32(bytes, 52),
            outcome: PublisherOutcome::read(bytes)?,
            final_raw_icount: get64(bytes, 64),
        };
        record.validate()?;

        Ok(record)
    }
}

/// Preserves producer destructor facts without certifying a Consumed transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherTerminal {
    /// Stable nonzero even producer terminal sequence.
    pub sequence: u64,
    /// Exact already retained offer, ticket, and command correlation.
    pub loan: PublisherLoanIdentity,
    /// Stable receiver return sequence to which these facts belong.
    pub receiver_return_sequence: u64,
    /// First semantic status, independently of actual destructor facts.
    pub first: i32,
    /// Independent post status; negative values never erase consumed facts.
    pub post: i32,
    /// Actual consumed memberships, a possibly incomplete subset of born rows.
    pub consumed_mask: u32,
    /// Nonempty actual born-membership mask within four rows.
    pub born_mask: u32,
    /// Actual command-borrower consumption generation, zero if unobserved.
    pub command_consumption_generation: u64,
}

impl PublisherTerminal {
    fn validate(self) -> Result<(), PublisherDecodeError> {
        self.loan.validate()?;
        if !sequence(self.sequence)
            || !sequence(self.receiver_return_sequence)
            || self.first > 0
            || self.post > 0
            || self.born_mask == 0
            || self.born_mask & !0xf != 0
            || self.consumed_mask & !self.born_mask != 0
            || self.command_consumption_generation == u64::MAX
        {
            return Err(PublisherDecodeError);
        }

        Ok(())
    }

    /// Encodes actual consumption metadata, preserving negative post statuses.
    ///
    /// # Errors
    /// Refuses malformed correlation, positive statuses, unknown born rows,
    /// consumption outside born rows, or an exhausted consumption generation.
    pub fn encode(self) -> Result<[u8; PUBLISHER_TERMINAL_BYTES], PublisherDecodeError> {
        self.validate()?;

        let mut bytes = [0; PUBLISHER_TERMINAL_BYTES];
        put64(&mut bytes, 0, self.sequence);
        self.loan.write(&mut bytes);
        put64(&mut bytes, 32, self.receiver_return_sequence);
        put32(&mut bytes, 40, self.first as u32);
        put32(&mut bytes, 44, self.post as u32);
        put32(&mut bytes, 48, self.consumed_mask);
        put32(&mut bytes, 52, self.born_mask);
        put64(&mut bytes, 56, self.command_consumption_generation);

        Ok(bytes)
    }

    /// Decodes one stable copied producer journal without repeating a release.
    ///
    /// # Errors
    /// Refuses short or trailing data, padding, malformed correlation, positive
    /// statuses, invalid masks, or an exhausted consumption generation.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_TERMINAL_BYTES || bytes[64..].iter().any(|byte| *byte != 0) {
            return Err(PublisherDecodeError);
        }

        let record = Self {
            sequence: get64(bytes, 0),
            loan: PublisherLoanIdentity::read(bytes),
            receiver_return_sequence: get64(bytes, 32),
            first: get32(bytes, 40) as i32,
            post: get32(bytes, 44) as i32,
            consumed_mask: get32(bytes, 48),
            born_mask: get32(bytes, 52),
            command_consumption_generation: get64(bytes, 56),
        };
        record.validate()?;

        Ok(record)
    }
}
