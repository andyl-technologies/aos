//! Encodes dormant Cleanup reservations without entering an operation.
//!
//! ```text
//! capability[384] = CRUCDCP1 | schema=1 | bytes=384 | profile=3 |
//!                   issuer/reservation/recipient/resource/outer identities |
//!                   six disjoint funding extents | future limits | zero padding
//! request[128] = CRUCDRQ1 | schema=1 | bytes=128 | reservation |
//!                immutable command correlation | termination history
//! entry[1024] = CRUCDEN1 | schema=1 | bytes=1024 | factual journal |
//!               optional actual CRUCACT2 cohort[896]
//! return[128] = CRUCDRT1 | schema=1 | bytes=128 | independent owner disposition
//! ```
//!
//! These records belong to the separately proposed Setup 9, plan 12, service 7,
//! publisher schema 3 profile. They do not extend the already-entered Cleanup
//! row in schema two or enable negotiation. A dormant capability has no clock
//! origin, entry coordinate or endpoint. Its future limits do not run during
//! Work. Decoding validates observations; it cannot issue a reservation, debit
//! resources, delegate entry authority, enter Cleanup or establish Current.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod entry;
pub use entry::{DEFERRED_CLEANUP_ENTRY_BYTES, DeferredCleanupEntry, DeferredCleanupEntryFacts};

mod physical_return;
pub use physical_return::{
    DEFERRED_CLEANUP_RETURN_BYTES, DeferredCleanupReturn, DeferredCleanupReturnFacts,
    DeferredCleanupReturnKind,
};

mod purpose;
pub use purpose::{
    DEFERRED_CLEANUP_PURPOSE_BYTES, DeferredCleanupDelegation, DeferredCleanupOuterPolicy,
    DeferredCleanupPurpose,
};

mod setup;
pub use setup::{DEFERRED_CLEANUP_SETUP_FRAME_BYTES, DeferredCleanupSetup};
#[cfg(unix)]
pub use setup::send_deferred_cleanup_setup_frame_with_descriptors;

#[cfg(test)]
mod tests;

/// Fixed extent of a dormant reservation record.
pub const DEFERRED_CLEANUP_CAPABILITY_BYTES: usize = 384;
/// Fixed extent of a once-only entry request record.
pub const DEFERRED_CLEANUP_REQUEST_BYTES: usize = 128;
/// Separately proposed setup edition; encoding does not enable this edition.
pub const DEFERRED_CLEANUP_SETUP: u32 = 9;
/// Separately proposed immutable plan edition.
pub const DEFERRED_CLEANUP_PLAN: u32 = 12;
/// Separately proposed local entry service edition.
pub const DEFERRED_CLEANUP_SERVICE: u32 = 7;
/// Publisher schema for dormant capabilities rather than entered intervals.
pub const DEFERRED_CLEANUP_PUBLISHER_SCHEMA: u32 = 3;

/// Refuses malformed syntax or mismatched reservation and command observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid deferred Cleanup observation")]
pub struct DeferredCleanupDecodeError;

/// Correlates an existing nominal owner and its nonwrapping incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredCleanupIdentity {
    /// Nonzero identity observed from the actual owning issuer.
    pub identity: [u8; 32],
    /// Existing incarnation, between one and `u64::MAX - 1` inclusive.
    pub incarnation: u64,
}

impl DeferredCleanupIdentity {
    fn validate(self) -> Result<(), DeferredCleanupDecodeError> {
        if self.identity == [0; 32] || !generation(self.incarnation) {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(())
    }
}

/// Reports six disjoint, already funded constituents of one physical child.
///
/// Every constituent is positive. Their checked sum is the physical extent;
/// a decoded amount neither allocates that extent nor proves actual funding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredCleanupFunding {
    /// Independently prepaid local control and service backing.
    pub control: u64,
    /// Complete owner, callback and external journal backing.
    pub journals: u64,
    /// Usable terminal stack backing, excluding guards.
    pub stack: u64,
    /// Separately paid native control and TLS backing.
    pub native: u64,
    /// Allocator backing, headers and retained allocation history.
    pub allocator: u64,
    /// Stack guards and mapping overhead.
    pub guards: u64,
}

impl DeferredCleanupFunding {
    /// Returns the checked extent of all six positive constituents.
    ///
    /// # Errors
    /// Refuses an absent constituent or a sum exceeding `u64::MAX`.
    pub fn total(self) -> Result<u64, DeferredCleanupDecodeError> {
        self.parts().into_iter().try_fold(0_u64, |sum, part| {
            if part == 0 {
                return Err(DeferredCleanupDecodeError);
            }
            sum.checked_add(part).ok_or(DeferredCleanupDecodeError)
        })
    }

    fn parts(self) -> [u64; 6] {
        [
            self.control,
            self.journals,
            self.stack,
            self.native,
            self.allocator,
            self.guards,
        ]
    }
}

/// Describes a retained once-only reservation without an entered interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredCleanupCapability {
    /// Actual delegated entry issuer.
    pub issuer: DeferredCleanupIdentity,
    /// Actual canonical dormant reservation.
    pub reservation: DeferredCleanupIdentity,
    /// Exact recipient of the retained reservation.
    pub recipient: DeferredCleanupIdentity,
    /// Existing resource subloan beneath the same local parent.
    pub resource: DeferredCleanupIdentity,
    /// Independently retained capability constraining future entry.
    pub outer: DeferredCleanupIdentity,
    /// Original positive even command publication sequence.
    pub command_sequence: u64,
    /// Actual immutable command loan incarnation.
    pub command_incarnation: u64,
    /// Issued ticket serial, at most `u64::MAX / 8`.
    pub ticket_serial: u64,
    /// Independently retained constituents of the actual physical child.
    pub funding: DeferredCleanupFunding,
    /// Nonzero identity of the complete concrete admission profile.
    pub profile: [u8; 32],
    /// Future entry duration limit; no interval begins when this is encoded.
    pub duration_ns: u64,
    /// Positive nonwrapping limit on future required work units.
    pub required_units: u64,
}

impl DeferredCleanupCapability {
    fn validate(&self) -> Result<(), DeferredCleanupDecodeError> {
        for identity in [
            self.issuer,
            self.reservation,
            self.recipient,
            self.resource,
            self.outer,
        ] {
            identity.validate()?;
        }
        self.funding.total()?;
        if !sequence(self.command_sequence)
            || !generation(self.command_incarnation)
            || !ticket(self.ticket_serial)
            || self.profile == [0; 32]
            || self.duration_ns == 0
            || self.duration_ns > i64::MAX as u64
            || !generation(self.required_units)
        {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(())
    }

    /// Encodes the dormant observation with canonical padding and funding sum.
    ///
    /// # Errors
    /// Refuses invalid identities, exhausted generations, invalid command
    /// correlation, absent profile, invalid future limits or invalid funding.
    pub fn encode(
        &self,
    ) -> Result<[u8; DEFERRED_CLEANUP_CAPABILITY_BYTES], DeferredCleanupDecodeError> {
        self.validate()?;
        let mut bytes = [0; DEFERRED_CLEANUP_CAPABILITY_BYTES];
        write_header(&mut bytes, b"CRUCDCP1");
        put32(&mut bytes, 16, DEFERRED_CLEANUP_PUBLISHER_SCHEMA);
        put32(&mut bytes, 20, 1);
        put32(&mut bytes, 28, 1);

        for (offset, identity) in [
            (32, self.issuer),
            (72, self.reservation),
            (112, self.recipient),
            (176, self.resource),
            (216, self.outer),
        ] {
            bytes[offset..offset + 32].copy_from_slice(&identity.identity);
            put64(&mut bytes, offset + 32, identity.incarnation);
        }
        put64(&mut bytes, 152, self.command_sequence);
        put64(&mut bytes, 160, self.command_incarnation);
        put64(&mut bytes, 168, self.ticket_serial);
        put64(&mut bytes, 256, self.funding.total()?);
        for (offset, amount) in [264, 272, 280, 288, 344, 352]
            .into_iter()
            .zip(self.funding.parts())
        {
            put64(&mut bytes, offset, amount);
        }
        bytes[296..328].copy_from_slice(&self.profile);
        put64(&mut bytes, 328, self.duration_ns);
        put64(&mut bytes, 336, self.required_units);
        Ok(bytes)
    }

    /// Decodes only the dormant capability edition and exact byte extent.
    ///
    /// # Errors
    /// Refuses malformed headers, flags, padding, identity, limits, funding
    /// overflow or a total that differs from the six constituent extents.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeferredCleanupDecodeError> {
        header(bytes, b"CRUCDCP1", DEFERRED_CLEANUP_CAPABILITY_BYTES)?;
        if get32(bytes, 16) != DEFERRED_CLEANUP_PUBLISHER_SCHEMA
            || get32(bytes, 20) != 1
            || get32(bytes, 24) != 0
            || get32(bytes, 28) != 1
            || bytes[360..].iter().any(|value| *value != 0)
        {
            return Err(DeferredCleanupDecodeError);
        }
        let capability = Self {
            issuer: identity(bytes, 32),
            reservation: identity(bytes, 72),
            recipient: identity(bytes, 112),
            resource: identity(bytes, 176),
            outer: identity(bytes, 216),
            command_sequence: get64(bytes, 152),
            command_incarnation: get64(bytes, 160),
            ticket_serial: get64(bytes, 168),
            funding: DeferredCleanupFunding {
                control: get64(bytes, 264),
                journals: get64(bytes, 272),
                stack: get64(bytes, 280),
                native: get64(bytes, 288),
                allocator: get64(bytes, 344),
                guards: get64(bytes, 352),
            },
            profile: array32(bytes, 296),
            duration_ns: get64(bytes, 328),
            required_units: get64(bytes, 336),
        };
        capability.validate()?;
        if capability.funding.total()? != get64(bytes, 256) {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(capability)
    }
}

/// Names the actual irreversible Work-termination producer history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DeferredCleanupReason {
    /// Work returned normally.
    Normal = 1,
    /// Work left through its genuine longjmp boundary.
    Longjmp = 2,
    /// Work left through its genuine atomic unwind boundary.
    Atomic = 3,
    /// Construction or execution was genuinely refused.
    Refusal = 4,
    /// The actual Work permission was revoked.
    Revocation = 5,
}

impl DeferredCleanupReason {
    fn decode(value: u32) -> Result<Self, DeferredCleanupDecodeError> {
        match value {
            1 => Ok(Self::Normal),
            2 => Ok(Self::Longjmp),
            3 => Ok(Self::Atomic),
            4 => Ok(Self::Refusal),
            5 => Ok(Self::Revocation),
            _ => Err(DeferredCleanupDecodeError),
        }
    }
}

/// Reports one request bound to a retained reservation and termination journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredCleanupRequest {
    /// Positive even publication sequence for this immutable request.
    pub sequence: u64,
    /// Exact dormant reservation named by the request.
    pub reservation: DeferredCleanupIdentity,
    /// Exact recipient incarnation retained before the request.
    pub recipient_incarnation: u64,
    /// Exact original command publication sequence.
    pub command_sequence: u64,
    /// Exact original issued ticket serial.
    pub ticket_serial: u64,
    /// Actual irreversible Work-termination journal incarnation.
    pub termination_incarnation: u64,
    /// Genuine producer path for that termination history.
    pub reason: DeferredCleanupReason,
}

impl DeferredCleanupRequest {
    fn validate(&self) -> Result<(), DeferredCleanupDecodeError> {
        self.reservation.validate()?;
        if !sequence(self.sequence)
            || !generation(self.recipient_incarnation)
            || !sequence(self.command_sequence)
            || !ticket(self.ticket_serial)
            || !generation(self.termination_incarnation)
        {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(())
    }

    /// Checks correlation with one capability without adopting its authority.
    ///
    /// # Errors
    /// Refuses invalid records or another reservation, recipient or command.
    pub fn validate_for(
        &self,
        capability: &DeferredCleanupCapability,
    ) -> Result<(), DeferredCleanupDecodeError> {
        self.validate()?;
        capability.validate()?;
        if self.reservation != capability.reservation
            || self.recipient_incarnation != capability.recipient.incarnation
            || self.command_sequence != capability.command_sequence
            || self.ticket_serial != capability.ticket_serial
        {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(())
    }

    /// Encodes the immutable request without entering Cleanup.
    ///
    /// # Errors
    /// Refuses absent or exhausted identities, invalid sequences or tickets.
    pub fn encode(
        &self,
    ) -> Result<[u8; DEFERRED_CLEANUP_REQUEST_BYTES], DeferredCleanupDecodeError> {
        self.validate()?;
        let mut bytes = [0; DEFERRED_CLEANUP_REQUEST_BYTES];
        write_header(&mut bytes, b"CRUCDRQ1");
        put64(&mut bytes, 16, self.sequence);
        bytes[24..56].copy_from_slice(&self.reservation.identity);
        for (offset, value) in [
            (56, self.reservation.incarnation),
            (64, self.recipient_incarnation),
            (72, self.command_sequence),
            (80, self.ticket_serial),
            (88, self.termination_incarnation),
        ] {
            put64(&mut bytes, offset, value);
        }
        put32(&mut bytes, 96, self.reason as u32);
        Ok(bytes)
    }

    /// Decodes an exact request observation, preserving its termination reason.
    ///
    /// # Errors
    /// Refuses invalid framing, padding, identities, sequences or reasons.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeferredCleanupDecodeError> {
        header(bytes, b"CRUCDRQ1", DEFERRED_CLEANUP_REQUEST_BYTES)?;
        if bytes[100..].iter().any(|value| *value != 0) {
            return Err(DeferredCleanupDecodeError);
        }
        let request = Self {
            sequence: get64(bytes, 16),
            reservation: identity(bytes, 24),
            recipient_incarnation: get64(bytes, 64),
            command_sequence: get64(bytes, 72),
            ticket_serial: get64(bytes, 80),
            termination_incarnation: get64(bytes, 88),
            reason: DeferredCleanupReason::decode(get32(bytes, 96))?,
        };
        request.validate()?;
        Ok(request)
    }
}

fn generation(value: u64) -> bool {
    value != 0 && value != u64::MAX
}

fn sequence(value: u64) -> bool {
    generation(value) && value & 1 == 0
}

fn ticket(value: u64) -> bool {
    (1..=u64::MAX / 8).contains(&value)
}

fn header(
    bytes: &[u8],
    magic: &[u8; 8],
    expected: usize,
) -> Result<(), DeferredCleanupDecodeError> {
    if bytes.len() != expected
        || bytes[..8] != *magic
        || get32(bytes, 8) != 1
        || get32(bytes, 12) as usize != expected
    {
        return Err(DeferredCleanupDecodeError);
    }
    Ok(())
}

fn write_header(bytes: &mut [u8], magic: &[u8; 8]) {
    let extent = bytes.len() as u32;
    bytes[..8].copy_from_slice(magic);
    put32(bytes, 8, 1);
    put32(bytes, 12, extent);
}

fn array32(bytes: &[u8], offset: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(&bytes[offset..offset + 32]);
    value
}

fn identity(bytes: &[u8], offset: usize) -> DeferredCleanupIdentity {
    DeferredCleanupIdentity {
        identity: array32(bytes, offset),
        incarnation: get64(bytes, offset + 32),
    }
}

fn get32(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(value)
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(value)
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
