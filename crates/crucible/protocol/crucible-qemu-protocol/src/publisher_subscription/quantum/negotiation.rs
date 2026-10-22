//! Encodes the distinct Setup7 and sealed Purpose2 Quantum observations.
//!
//! ```text
//! setup[125]: BEu32(121) | tag=0x17 | existing payload | schema=2 | flags=1 | zero[8]
//! purpose[224]: CRUCPSP2 | schema=2 | bytes=224 | existing identity[176] |
//!               region=2:u32 | roles=1:u32 | variant=1:u32 | flags=0:u32 |
//!               terminal_contract=1:u64 | zero[8]
//! ```
//!
//! These bounded codecs do not select the active route, receive descriptors,
//! authenticate a sealed file or create an independent Cleanup operation.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::super::{
    PUBLISHER_PURPOSE_BYTES, PUBLISHER_SETUP_FRAME_BYTES, PublisherDecodeError, PublisherPurpose,
    PublisherSetup, get32, get64, put32, put64,
};
use super::QuantumPublisherHeader;

/// Describes Setup7's exact Quantum-only publisher transport observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantumPublisherSetup {
    /// Unchanged physical roles, identities and optional workspace binding.
    pub transport: PublisherSetup,
}

impl QuantumPublisherSetup {
    /// Encodes the distinct Setup7 tag and mapping edition.
    ///
    /// # Errors
    /// Refuses invalid physical identities, events or workspace syntax.
    pub fn encode(&self) -> Result<[u8; PUBLISHER_SETUP_FRAME_BYTES], PublisherDecodeError> {
        let mut bytes = self.transport.encode()?;
        bytes[4] = 0x17;
        put32(&mut bytes, 109, 2);
        Ok(bytes)
    }

    /// Decodes only Setup7 without accepting another transport edition.
    ///
    /// # Errors
    /// Refuses malformed framing, geometry, identities, padding or workspace
    /// syntax, including a mixed Setup6 tag and schema-two mapping.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_SETUP_FRAME_BYTES || bytes[4] != 0x17 || get32(bytes, 109) != 2
        {
            return Err(PublisherDecodeError);
        }

        // Establish the new edition first, then share the fixed physical-field
        // validator. No second transport receive or decoding fallback occurs.
        let mut common = [0; PUBLISHER_SETUP_FRAME_BYTES];
        common.copy_from_slice(bytes);
        common[4] = 0x16;
        put32(&mut common, 109, 1);
        Ok(Self {
            transport: PublisherSetup::decode(&common)?,
        })
    }
}

/// Describes Purpose2's explicit mapping, role and terminal contract editions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuantumPublisherPurpose {
    /// Unchanged physical storage and actual Source identity observations.
    pub session: PublisherPurpose,
}

impl QuantumPublisherPurpose {
    /// Encodes the exact sealed schema-two subscription purpose.
    ///
    /// Physical storage cleanup generation remains one. It is independent of
    /// the actual Cleanup operation loan and entered interval incarnations.
    ///
    /// # Errors
    /// Refuses invalid physical lender, account, process or event identities.
    pub fn encode(&self) -> Result<[u8; PUBLISHER_PURPOSE_BYTES], PublisherDecodeError> {
        let mut bytes = self.session.encode()?;
        bytes[..8].copy_from_slice(b"CRUCPSP2");
        put32(&mut bytes, 8, 2);
        put32(&mut bytes, 192, 2);
        put32(&mut bytes, 196, 1);
        put32(&mut bytes, 200, 1);
        put64(&mut bytes, 208, 1);
        Ok(bytes)
    }

    /// Decodes only the exact Quantum-only Purpose2 contract.
    ///
    /// # Errors
    /// Refuses another edition, unknown role/variant/terminal contracts,
    /// changed geometry, invalid identities, flags or reserved bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_PURPOSE_BYTES
            || bytes[..8] != *b"CRUCPSP2"
            || get32(bytes, 8) != 2
            || get32(bytes, 192) != 2
            || get32(bytes, 196) != 1
            || get32(bytes, 200) != 1
            || get32(bytes, 204) != 0
            || get64(bytes, 208) != 1
            || bytes[216..].iter().any(|byte| *byte != 0)
        {
            return Err(PublisherDecodeError);
        }

        let mut common = [0; PUBLISHER_PURPOSE_BYTES];
        common.copy_from_slice(bytes);
        common[..8].copy_from_slice(b"CRUCPSP1");
        put32(&mut common, 8, 1);
        common[192..].fill(0);
        Ok(Self {
            session: PublisherPurpose::decode(&common)?,
        })
    }

    /// Checks corresponding decoded Setup7, Purpose2 and schema-two identities.
    ///
    /// This checks observations only. Actual endpoint, sealed-plan and mapping
    /// owners must separately authenticate the exact same physical objects.
    ///
    /// # Errors
    /// Refuses invalid syntax or any changed lender, Source, file or event
    /// identity across the three decoded observations.
    pub fn validate_correspondence(
        &self,
        setup: &QuantumPublisherSetup,
        header: &QuantumPublisherHeader,
    ) -> Result<(), PublisherDecodeError> {
        self.encode()?;
        setup.encode()?;
        header.encode()?;
        let purpose = &self.session;
        let setup = &setup.transport;
        let header = &header.identity;
        if purpose.lender_generation != setup.lender_generation
            || purpose.lender_generation != header.lender_generation
            || purpose.account_generation != header.account_generation
            || purpose.process_generation != setup.process_generation
            || purpose.process_generation != header.process_generation
            || purpose.capability != header.capability
            || purpose.reservation != header.reservation
            || purpose.device != setup.device
            || purpose.inode != setup.inode
            || purpose.producer_event != setup.producer_event
            || purpose.receiver_event != setup.receiver_event
        {
            return Err(PublisherDecodeError);
        }
        Ok(())
    }
}

/// Sends Setup7 with exactly eight or nine borrowed physical aliases.
///
/// This sends the distinct Quantum frame once. The caller authenticates and
/// retains every role, including after a partial or uncertain handover.
///
/// # Errors
/// Refuses malformed or mixed editions, wrong roster size, negative descriptors,
/// non-socket endpoints or ancillary/write failure. A partial send never retries.
#[cfg(unix)]
pub fn send_quantum_publisher_setup_frame_with_descriptors(
    socket: std::os::fd::RawFd,
    frame: &[u8; PUBLISHER_SETUP_FRAME_BYTES],
    descriptors: &[std::os::fd::RawFd],
) -> Result<crate::PreexecSetupHandover, crate::DescriptorHandoverError> {
    let refused = || crate::DescriptorHandoverError::MalformedAncillary {
        reason: "Quantum publisher setup frame or descriptor roster differs",
    };
    let setup = QuantumPublisherSetup::decode(frame).map_err(|_| refused())?;
    let count = 8 + usize::from(setup.transport.device_digest_workspace.is_some());
    if descriptors.len() != count || descriptors.iter().any(|descriptor| *descriptor < 0) {
        return Err(refused());
    }

    let (device, inode) = crate::preexec_socket_identity(socket)?;
    crate::send_frame_with_fds(socket, frame, descriptors)?;
    Ok(crate::PreexecSetupHandover { device, inode })
}

#[cfg(test)]
mod tests;
