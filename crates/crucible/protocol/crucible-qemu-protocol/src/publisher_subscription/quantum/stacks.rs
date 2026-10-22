//! Encodes explicit Main/RR stack observations under the separate Setup8 tuple.
//!
//! ```text
//! Setup8[125]: Setup7 physical fields | tag 0x18 | grant-set:u64 at 117
//! CRUCSTK1[576]: header64 | Main256 | RR256
//! header: magic/schema/header/bytes/count | set/process/account/lender:u64 | zero8
//! role: role/flags:u32 | loan/account/process:u64 | cap32 | reservation32 |
//!       usable/guards/mapping/control/TLS/page/soft/hard:u64 | profile32 |
//!       cleanup/births/attempts/borrowers:u64 | zero32
//! ```
//!
//! These pure checked observations issue no stack, allocator, process, operation
//! or cleanup owner. Actual issuers retain and reconcile both nominal subloans
//! beneath the same real native account before process or thread creation.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{QuantumPublisherHeader, QuantumPublisherPurpose, QuantumPublisherSetup};
use super::super::{PUBLISHER_SETUP_FRAME_BYTES, PublisherDecodeError, generation, get64, put32, put64};

/// Fixed encoded extent of the stack section selected by plan eleven.
pub const QUANTUM_STACK_PURPOSE_BYTES: usize = 576;

/// Describes Setup8's exact physical roles and retained grant-set incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantumStackPublisherSetup {
    /// Exact schema-two publisher and optional workspace observations.
    pub publisher: QuantumPublisherSetup,
    /// Nonexhausted incarnation of the actual retained parent grant set.
    pub grant_set_generation: u64,
}

impl QuantumStackPublisherSetup {
    /// Encodes Setup8 without changing an earlier edition's reserved bytes.
    ///
    /// # Errors
    /// Refuses invalid physical roles or a missing/exhausted grant incarnation.
    pub fn encode(&self) -> Result<[u8; PUBLISHER_SETUP_FRAME_BYTES], PublisherDecodeError> {
        if !generation(self.grant_set_generation) {
            return Err(PublisherDecodeError);
        }
        let mut bytes = self.publisher.encode()?;
        bytes[4] = 0x18;
        put64(&mut bytes, 117, self.grant_set_generation);
        Ok(bytes)
    }

    /// Decodes only the exact Setup8 transport edition.
    ///
    /// # Errors
    /// Refuses other tags, malformed physical fields, reserved bytes or a
    /// missing/exhausted grant incarnation. No fallback receive is performed.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_SETUP_FRAME_BYTES
            || bytes[4] != 0x18
            || !generation(get64(bytes, 117))
        {
            return Err(PublisherDecodeError);
        }
        let mut common = [0; PUBLISHER_SETUP_FRAME_BYTES];
        common.copy_from_slice(bytes);
        common[4] = 0x17;
        common[117..].fill(0);
        Ok(Self {
            publisher: QuantumPublisherSetup::decode(&common)?,
            grant_set_generation: get64(bytes, 117),
        })
    }
}

/// Sends exactly one Setup8 frame with eight or nine borrowed physical aliases.
///
/// Actual issuers retain each descriptor and the nominal stack parents through
/// partial or uncertain handover. This operation creates no resource grant.
///
/// # Errors
/// Refuses malformed or other editions, a wrong roster, negative descriptors,
/// an invalid socket, or ancillary/write failure. A partial send never retries.
#[cfg(unix)]
pub fn send_quantum_stack_setup_frame_with_descriptors(
    socket: std::os::fd::RawFd,
    frame: &[u8; PUBLISHER_SETUP_FRAME_BYTES],
    descriptors: &[std::os::fd::RawFd],
) -> Result<crate::PreexecSetupHandover, crate::DescriptorHandoverError> {
    let refused = || crate::DescriptorHandoverError::MalformedAncillary {
        reason: "Quantum stack setup frame or descriptor roster differs",
    };
    let setup = QuantumStackPublisherSetup::decode(frame).map_err(|_| refused())?;
    let count = 8 + usize::from(setup.publisher.transport.device_digest_workspace.is_some());
    if descriptors.len() != count || descriptors.iter().any(|descriptor| *descriptor < 0) {
        return Err(refused());
    }

    let (device, inode) = crate::preexec_socket_identity(socket)?;
    crate::send_frame_with_fds(socket, frame, descriptors)?;
    Ok(crate::PreexecSetupHandover { device, inode })
}

/// Describes one retained stack reservation without constructing its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantumStackReservation {
    /// Actual recipient-specific resource-loan incarnation.
    pub loan_generation: u64,
    /// Finite usable stack extent, including all admitted call and tail use.
    pub usable_bytes: u64,
    /// Complete mapping extent, including actual RR guards or Main rounding.
    pub mapping_bytes: u64,
    /// Separately admitted native thread-control inventory.
    pub thread_control_bytes: u64,
    /// Separately admitted native loader and TLS inventory.
    pub loader_tls_bytes: u64,
    /// Actual supported host page geometry, independently checked at adoption.
    pub page_bytes: u64,
    /// Nonzero digest of the concrete independently admitted resource profile.
    pub profile_digest: [u8; 32],
    /// Actual independent physical cleanup-holder incarnation.
    pub cleanup_generation: u64,
}

impl QuantumStackReservation {
    fn geometry(&self, main: bool) -> Result<u64, PublisherDecodeError> {
        if !generation(self.loan_generation)
            || !generation(self.cleanup_generation)
            || self.usable_bytes == 0
            || self.usable_bytes == u64::MAX
            || self.page_bytes == 0
            || self.profile_digest == [0; 32]
        {
            return Err(PublisherDecodeError);
        }
        let guards = if main {
            0
        } else {
            if !self.usable_bytes.is_multiple_of(self.page_bytes) {
                return Err(PublisherDecodeError);
            }
            self.page_bytes.checked_mul(2).ok_or(PublisherDecodeError)?
        };
        let mapping = if main {
            let remainder = self.usable_bytes % self.page_bytes;
            self.usable_bytes.checked_add(if remainder == 0 {
                0
            } else {
                self.page_bytes - remainder
            })
        } else {
            self.usable_bytes.checked_add(guards)
        };
        if mapping != Some(self.mapping_bytes) || self.mapping_bytes == u64::MAX {
            return Err(PublisherDecodeError);
        }
        self.reserved_bytes()?;
        Ok(guards)
    }

    /// Reports the checked mapping, control and TLS inventory sum.
    ///
    /// This is a requested/observed extent, never independently spendable credit.
    ///
    /// # Errors
    /// Refuses an overflowing per-role inventory.
    pub fn reserved_bytes(&self) -> Result<u64, PublisherDecodeError> {
        self.mapping_bytes
            .checked_add(self.thread_control_bytes)
            .and_then(|bytes| bytes.checked_add(self.loader_tls_bytes))
            .ok_or(PublisherDecodeError)
    }
}

/// Correlates the two fixed stack-role observations with their actual parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantumStackPurpose {
    /// Actual retained parent grant-set incarnation.
    pub grant_set_generation: u64,
    /// Actual Source process incarnation selected by the sealed purpose.
    pub process_generation: u64,
    /// Actual containing native account generation.
    pub account_generation: u64,
    /// Same physical setup and publisher lender incarnation.
    pub lender_generation: u64,
    /// Nonzero containing capability identity corroborated by real owners.
    pub capability: [u8; 32],
    /// Nonzero process resource reservation identity corroborated by real owners.
    pub reservation: [u8; 32],
    /// Exec Main stack reservation, fixed role one.
    pub main: QuantumStackReservation,
    /// Shared RR stack reservation, fixed role two.
    pub rr: QuantumStackReservation,
}

impl QuantumStackPurpose {
    /// Reports both checked role totals without debiting or issuing an account.
    ///
    /// # Errors
    /// Refuses overflow within either role or the aggregate inventory.
    pub fn reserved_bytes(&self) -> Result<u64, PublisherDecodeError> {
        self.main
            .reserved_bytes()?
            .checked_add(self.rr.reserved_bytes()?)
            .ok_or(PublisherDecodeError)
    }

    /// Encodes the exact header and two fixed-position stack observations.
    ///
    /// # Errors
    /// Refuses invalid identities, exhausted generations, mapping/page geometry,
    /// missing profiles or overflowing role/aggregate inventories.
    pub fn encode(&self) -> Result<[u8; QUANTUM_STACK_PURPOSE_BYTES], PublisherDecodeError> {
        if ![
            self.grant_set_generation,
            self.process_generation,
            self.account_generation,
            self.lender_generation,
        ]
        .into_iter()
        .all(generation)
            || self.capability == [0; 32]
            || self.reservation == [0; 32]
            || self.main.page_bytes != self.rr.page_bytes
        {
            return Err(PublisherDecodeError);
        }
        self.reserved_bytes()?;
        let mut bytes = [0; QUANTUM_STACK_PURPOSE_BYTES];
        bytes[..8].copy_from_slice(b"CRUCSTK1");
        for (offset, value) in [(8, 1), (12, 64), (16, 576), (20, 2)] {
            put32(&mut bytes, offset, value);
        }
        for (offset, value) in [
            (24, self.grant_set_generation),
            (32, self.process_generation),
            (40, self.account_generation),
            (48, self.lender_generation),
        ] {
            put64(&mut bytes, offset, value);
        }
        for (index, record) in [self.main, self.rr].iter().enumerate() {
            let main = index == 0;
            let guards = record.geometry(main)?;
            let role = &mut bytes[64 + index * 256..64 + (index + 1) * 256];
            put32(role, 0, index as u32 + 1);
            for (offset, value) in [
                (8, record.loan_generation),
                (16, self.account_generation),
                (24, self.process_generation),
                (96, record.usable_bytes),
                (104, guards),
                (112, record.mapping_bytes),
                (120, record.thread_control_bytes),
                (128, record.loader_tls_bytes),
                (136, record.page_bytes),
                (144, if main { record.usable_bytes } else { 0 }),
                (152, if main { record.usable_bytes } else { 0 }),
                (192, record.cleanup_generation),
                (200, 1),
                (208, 1),
                (216, 1),
            ] {
                put64(role, offset, value);
            }
            role[32..64].copy_from_slice(&self.capability);
            role[64..96].copy_from_slice(&self.reservation);
            role[160..192].copy_from_slice(&record.profile_digest);
        }
        Ok(bytes)
    }

    /// Decodes exactly one stack section and withholds malformed observations.
    ///
    /// # Errors
    /// Refuses other editions, truncation, trailing data, unknown roles, flags,
    /// padding, changed role identities, invalid geometry or inventory overflow.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != QUANTUM_STACK_PURPOSE_BYTES {
            return Err(PublisherDecodeError);
        }
        let record = |offset| -> Result<QuantumStackReservation, PublisherDecodeError> {
            let row = &bytes[offset..offset + 256];
            Ok(QuantumStackReservation {
                loan_generation: get64(row, 8),
                usable_bytes: get64(row, 96),
                mapping_bytes: get64(row, 112),
                thread_control_bytes: get64(row, 120),
                loader_tls_bytes: get64(row, 128),
                page_bytes: get64(row, 136),
                profile_digest: row[160..192].try_into().map_err(|_| PublisherDecodeError)?,
                cleanup_generation: get64(row, 192),
            })
        };
        let purpose = Self {
            grant_set_generation: get64(bytes, 24),
            process_generation: get64(bytes, 32),
            account_generation: get64(bytes, 40),
            lender_generation: get64(bytes, 48),
            capability: bytes[96..128]
                .try_into()
                .map_err(|_| PublisherDecodeError)?,
            reservation: bytes[128..160]
                .try_into()
                .map_err(|_| PublisherDecodeError)?,
            main: record(64)?,
            rr: record(320)?,
        };
        // Exact reconstruction also checks every fixed field, repeated identity,
        // physical limit, guard extent and reserved byte before exposing data.
        if purpose.encode()?.as_slice() != bytes {
            return Err(PublisherDecodeError);
        }
        Ok(purpose)
    }

    /// Corroborates matched Setup8, Purpose2 and stack parent observations.
    ///
    /// Concrete profile/page checks and genuine owner retention remain separate.
    ///
    /// # Errors
    /// Refuses invalid syntax or changed lender, account, process, capability,
    /// reservation or grant-set incarnation across the selected records.
    pub fn validate_correspondence(
        &self,
        setup: &QuantumStackPublisherSetup,
        publisher: &QuantumPublisherPurpose,
        header: &QuantumPublisherHeader,
    ) -> Result<(), PublisherDecodeError> {
        self.encode()?;
        setup.encode()?;
        publisher.validate_correspondence(&setup.publisher, header)?;
        let session = publisher.session;
        if self.grant_set_generation != setup.grant_set_generation
            || self.process_generation != session.process_generation
            || self.account_generation != session.account_generation
            || self.lender_generation != session.lender_generation
            || self.capability != session.capability
            || self.reservation != session.reservation
        {
            return Err(PublisherDecodeError);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
