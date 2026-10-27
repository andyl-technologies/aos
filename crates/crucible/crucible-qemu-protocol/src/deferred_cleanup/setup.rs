//! Frames the separate Setup-nine carrier and its exact descriptor roster.
//!
//! ```text
//! BEu32(121) | tag0x19 | ordinary payload[56] | publisher roles[48] |
//! schema3:u32 | role-map2:u32 | delegation-incarnation:u64
//! SCM: shmem, wake, plan, standing publication, cancellation, workspace?,
//!      publisher memory, producer event, receiver event
//! ```
//!
//! Encoding and sending cannot issue a delegation or admit its runtime profile.
//! The genuine installer must authenticate the retained parents and carrier.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{DeferredCleanupDecodeError, generation, get64};
use crate::publisher_subscription::{PUBLISHER_SETUP_FRAME_BYTES, PublisherSetup};

/// Exact framed extent of the separately proposed Setup-nine edition.
pub const DEFERRED_CLEANUP_SETUP_FRAME_BYTES: usize = PUBLISHER_SETUP_FRAME_BYTES;

/// Describes physical setup roles and one retained delegation incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredCleanupSetup {
    /// Existing physical role observations, without ownership or permission.
    pub publisher: PublisherSetup,
    /// Nonzero, nonexhausted incarnation of the actually retained delegation.
    pub delegation_incarnation: u64,
}

impl DeferredCleanupSetup {
    fn validate(&self) -> Result<(), DeferredCleanupDecodeError> {
        if !generation(self.delegation_incarnation)
            || !generation(self.publisher.process_generation)
            || self
                .publisher
                .device_digest_workspace
                .is_some_and(|binding| {
                    !generation(binding.account_generation)
                        || !generation(binding.workspace_generation)
                })
        {
            return Err(DeferredCleanupDecodeError);
        }
        Ok(())
    }

    /// Encodes only the exact proposed edition without allocating or activating it.
    ///
    /// # Errors
    /// Refuses malformed physical roles, absent or exhausted incarnations,
    /// invalid events or incomplete optional workspace observations.
    pub fn encode(
        &self,
    ) -> Result<[u8; DEFERRED_CLEANUP_SETUP_FRAME_BYTES], DeferredCleanupDecodeError> {
        self.validate()?;
        let mut bytes = self
            .publisher
            .encode()
            .map_err(|_| DeferredCleanupDecodeError)?;
        bytes[4] = 0x19;
        bytes[109..113].copy_from_slice(&3_u32.to_be_bytes());
        bytes[113..117].copy_from_slice(&2_u32.to_be_bytes());
        bytes[117..125].copy_from_slice(&self.delegation_incarnation.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes only Setup nine with its mandatory incarnation-bearing footer.
    ///
    /// # Errors
    /// Refuses mixed editions, malformed physical roles or workspace flags,
    /// invalid or exhausted incarnations, truncation and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeferredCleanupDecodeError> {
        if bytes.len() != DEFERRED_CLEANUP_SETUP_FRAME_BYTES
            || bytes[4] != 0x19
            || bytes[109..113] != 3_u32.to_be_bytes()
            || bytes[113..117] != 2_u32.to_be_bytes()
        {
            return Err(DeferredCleanupDecodeError);
        }
        let delegation_incarnation = get64(bytes, 117);
        // Validate common physical geometry through its original parser. This
        // private copy never makes the old decoder accept the new wire edition.
        let mut physical = [0; PUBLISHER_SETUP_FRAME_BYTES];
        physical.copy_from_slice(bytes);
        physical[4] = 0x16;
        physical[109..113].copy_from_slice(&1_u32.to_be_bytes());
        physical[113..117].copy_from_slice(&1_u32.to_be_bytes());
        physical[117..].fill(0);
        let setup = Self {
            publisher: PublisherSetup::decode(&physical).map_err(|_| DeferredCleanupDecodeError)?,
            delegation_incarnation,
        };
        setup.validate()?;
        Ok(setup)
    }
}

/// Sends the exact Setup-nine frame with its eight or nine borrowed roles.
///
/// The optional workspace stays before the three publisher roles. The caller
/// authenticates and retains all actual owners through uncertain delivery and
/// process collection. A successful socket write supplies no entry permission.
///
/// # Errors
/// Refuses malformed framing, a mismatched roster, negative descriptors,
/// non-socket endpoints and ancillary/send failures. Partial delivery is never
/// retried; the caller must retain the same aliases and physical return debt.
#[cfg(unix)]
pub fn send_deferred_cleanup_setup_frame_with_descriptors(
    socket: std::os::fd::RawFd,
    frame: &[u8; DEFERRED_CLEANUP_SETUP_FRAME_BYTES],
    descriptors: &[std::os::fd::RawFd],
) -> Result<crate::PreexecSetupHandover, crate::DescriptorHandoverError> {
    let refused = || crate::DescriptorHandoverError::MalformedAncillary {
        reason: "deferred Cleanup pre-exec frame or descriptor roster differs",
    };
    let setup = DeferredCleanupSetup::decode(frame).map_err(|_| refused())?;
    let count = 8 + usize::from(setup.publisher.device_digest_workspace.is_some());
    if descriptors.len() != count || descriptors.iter().any(|descriptor| *descriptor < 0) {
        return Err(refused());
    }

    let (device, inode) = crate::preexec_socket_identity(socket)?;
    crate::send_frame_with_fds(socket, frame, descriptors)?;
    Ok(crate::PreexecSetupHandover { device, inode })
}

#[cfg(test)]
mod tests;
