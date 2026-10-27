//! Encodes sealed corroboration for the publisher's physical session roles.
//!
//! ```text
//! CRUCPSP1 | schema:u32 | bytes:u32 | lender/account/process:u64 |
//! capability[32] | reservation[32] | device/inode/region:u64 |
//! producer_event/receiver_event/backing/cleanup/native:u64 |
//! aliases:u64=3 | file_bytes:u64=4096 | flags:u64=1 | zero[32]
//! ```
//!
//! These facts neither create a lender nor pay for a mapping or queued alias.
//! The actual session constructors must retain and authenticate their owners.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{PUBLISHER_REGION_BYTES, PublisherDecodeError, generation, get64};

/// Fixed byte extent of sealed publisher session corroboration.
pub const PUBLISHER_PURPOSE_BYTES: usize = 224;

/// Describes a publisher session's physical roles without granting custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherPurpose {
    /// Nonzero, nonexhausted generation of the actual lender.
    pub lender_generation: u64,
    /// Containing Source account incarnation.
    pub account_generation: u64,
    /// Source process incarnation.
    pub process_generation: u64,
    /// Containing Source capability identity.
    pub capability: [u8; 32],
    /// Actual Source reservation identity.
    pub reservation: [u8; 32],
    /// Exact kernel device identity of the region file.
    pub device: u64,
    /// Exact kernel inode identity of the region file.
    pub inode: u64,
    /// Encoded event identity for producer-to-receiver notification.
    pub producer_event: u64,
    /// Distinct encoded event identity for receiver-to-producer notification.
    pub receiver_event: u64,
    /// Receiver mapping reserve rounded to its actual host page size.
    pub backing_bytes: u64,
}

impl PublisherPurpose {
    fn validate(&self) -> Result<(), PublisherDecodeError> {
        if !generation(self.lender_generation)
            || !generation(self.account_generation)
            || !generation(self.process_generation)
            || self.capability == [0; 32]
            || self.reservation == [0; 32]
            || !generation(self.producer_event)
            || !generation(self.receiver_event)
            || self.producer_event == self.receiver_event
            || self.backing_bytes < PUBLISHER_REGION_BYTES as u64
        {
            return Err(PublisherDecodeError);
        }

        Ok(())
    }

    /// Encodes the fixed role geometry and independent cleanup declaration.
    ///
    /// Cleanup generation one describes the once-constructed receiver holder;
    /// this record cannot initialize that holder or discharge its debit.
    ///
    /// # Errors
    /// Refuses absent or exhausted identities, aliased events or short backing.
    pub fn encode(&self) -> Result<[u8; PUBLISHER_PURPOSE_BYTES], PublisherDecodeError> {
        self.validate()?;

        let mut bytes = [0; PUBLISHER_PURPOSE_BYTES];
        bytes[..8].copy_from_slice(b"CRUCPSP1");
        bytes[8..12].copy_from_slice(&1_u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&(PUBLISHER_PURPOSE_BYTES as u32).to_be_bytes());
        bytes[40..72].copy_from_slice(&self.capability);
        bytes[72..104].copy_from_slice(&self.reservation);
        for (offset, value) in [
            (16, self.lender_generation),
            (24, self.account_generation),
            (32, self.process_generation),
            (104, self.device),
            (112, self.inode),
            (120, PUBLISHER_REGION_BYTES as u64),
            (128, self.producer_event),
            (136, self.receiver_event),
            (144, self.backing_bytes),
            (152, 1),
            (160, self.backing_bytes),
            (168, 3),
            (176, PUBLISHER_REGION_BYTES as u64),
            (184, 1),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }

        Ok(bytes)
    }

    /// Decodes exact sealed role corroboration without allocating or issuing it.
    ///
    /// Page rounding is checked by the real receiver against its host page
    /// size; the wire only requires enough backing and the equal native debit.
    /// Device and inode are exact witnesses and may contain zero.
    ///
    /// # Errors
    /// Refuses noncanonical length, framing, geometry, debit, cleanup, padding
    /// or identities, including equal notification events.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_PURPOSE_BYTES
            || bytes[..8] != *b"CRUCPSP1"
            || bytes[8..12] != 1_u32.to_be_bytes()
            || bytes[12..16] != (PUBLISHER_PURPOSE_BYTES as u32).to_be_bytes()
            || get64(bytes, 120) != PUBLISHER_REGION_BYTES as u64
            || get64(bytes, 152) != 1
            || get64(bytes, 160) != get64(bytes, 144)
            || get64(bytes, 168) != 3
            || get64(bytes, 176) != PUBLISHER_REGION_BYTES as u64
            || get64(bytes, 184) != 1
            || bytes[192..].iter().any(|byte| *byte != 0)
        {
            return Err(PublisherDecodeError);
        }

        let mut capability = [0; 32];
        capability.copy_from_slice(&bytes[40..72]);
        let mut reservation = [0; 32];
        reservation.copy_from_slice(&bytes[72..104]);
        let purpose = Self {
            lender_generation: get64(bytes, 16),
            account_generation: get64(bytes, 24),
            process_generation: get64(bytes, 32),
            capability,
            reservation,
            device: get64(bytes, 104),
            inode: get64(bytes, 112),
            producer_event: get64(bytes, 128),
            receiver_event: get64(bytes, 136),
            backing_bytes: get64(bytes, 144),
        };
        purpose.validate()?;

        Ok(purpose)
    }
}
