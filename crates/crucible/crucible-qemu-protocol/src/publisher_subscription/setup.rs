//! Encodes the preparation-only publisher setup frame and its descriptor roster.
//!
//! ```text
//! BEu32(121) | tag:u8=0x16 | ordinary_setup_payload[56] |
//! lender/region/device/inode/producer_event/receiver_event:u64 |
//! schema:u32=1 | flags:u32=1 | zero[8]
//! SCM_RIGHTS: shared memory, wake, sealed plan, standing publication,
//! standing cancellation, optional workspace, publisher region,
//! producer event, receiver event
//! ```
//!
//! This separate edition does not enter the activated control-tag registry.
//! Sending bytes proves neither a paid lender nor receiver admission; the real
//! launch owner must authenticate the plan, physical roles and Original.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{PUBLISHER_REGION_BYTES, PublisherDecodeError, generation, get64};
use crate::DeviceDigestWorkspaceBinding;

/// Exact framed extent of the preparation-only publisher setup edition.
pub const PUBLISHER_SETUP_FRAME_BYTES: usize = 125;

/// Describes the fixed setup observations without granting descriptor custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherSetup {
    /// Exact length of the ordinary shared-memory region.
    pub region_len: u64,
    /// Incarnation of the receiving Source process.
    pub process_generation: u64,
    /// Optional sixth descriptor's independently authenticated binding.
    pub device_digest_workspace: Option<DeviceDigestWorkspaceBinding>,
    /// Nonzero, nonexhausted actual publisher lender incarnation.
    pub lender_generation: u64,
    /// Exact publisher region file device identity, including zero.
    pub device: u64,
    /// Exact publisher region file inode identity, including zero.
    pub inode: u64,
    /// Producer-to-receiver notification event identity.
    pub producer_event: u64,
    /// Distinct receiver-to-producer notification event identity.
    pub receiver_event: u64,
}

impl PublisherSetup {
    fn validate(&self) -> Result<(), PublisherDecodeError> {
        if self.region_len == 0
            || self.process_generation == 0
            || !generation(self.lender_generation)
            || !generation(self.producer_event)
            || !generation(self.receiver_event)
            || self.producer_event == self.receiver_event
            || self.device_digest_workspace.is_some_and(|binding| {
                binding.account_generation == 0 || binding.workspace_generation == 0
            })
        {
            return Err(PublisherDecodeError);
        }

        Ok(())
    }

    /// Encodes one canonical fixed frame without allocating.
    ///
    /// # Errors
    /// Refuses absent region/process identities, invalid lender or event
    /// generations, equal events or incomplete workspace bindings.
    pub fn encode(&self) -> Result<[u8; PUBLISHER_SETUP_FRAME_BYTES], PublisherDecodeError> {
        self.validate()?;

        let mut bytes = [0; PUBLISHER_SETUP_FRAME_BYTES];
        bytes[..4].copy_from_slice(&121_u32.to_be_bytes());
        bytes[4] = 0x16;
        for (offset, value) in [
            (5, self.region_len),
            (21, self.process_generation),
            (61, self.lender_generation),
            (69, PUBLISHER_REGION_BYTES as u64),
            (77, self.device),
            (85, self.inode),
            (93, self.producer_event),
            (101, self.receiver_event),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        if let Some(binding) = self.device_digest_workspace {
            bytes[13..17].copy_from_slice(&1_u32.to_be_bytes());
            bytes[17..21].copy_from_slice(&2_u32.to_be_bytes());
            for (offset, value) in [
                (29, binding.account_generation),
                (37, binding.workspace_generation),
                (45, binding.device),
                (53, binding.inode),
            ] {
                bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            }
        }
        bytes[109..113].copy_from_slice(&1_u32.to_be_bytes());
        bytes[113..117].copy_from_slice(&1_u32.to_be_bytes());

        Ok(bytes)
    }

    /// Decodes only the exact publisher setup edition without allocating.
    ///
    /// # Errors
    /// Refuses truncation, trailing bytes, another edition, changed geometry,
    /// reserved bytes, invalid identities or noncanonical workspace presence.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublisherDecodeError> {
        if bytes.len() != PUBLISHER_SETUP_FRAME_BYTES
            || bytes[..4] != 121_u32.to_be_bytes()
            || bytes[4] != 0x16
            || get64(bytes, 69) != PUBLISHER_REGION_BYTES as u64
            || bytes[109..113] != 1_u32.to_be_bytes()
            || bytes[113..117] != 1_u32.to_be_bytes()
            || bytes[117..] != [0; 8]
        {
            return Err(PublisherDecodeError);
        }

        let device_digest_workspace = match (&bytes[13..17], &bytes[17..21]) {
            (schema, flags) if schema == [0; 4] && flags == [0; 4] => {
                if bytes[29..61] != [0; 32] {
                    return Err(PublisherDecodeError);
                }
                None
            }
            (schema, flags) if schema == 1_u32.to_be_bytes() && flags == 2_u32.to_be_bytes() => {
                Some(DeviceDigestWorkspaceBinding {
                    account_generation: get64(bytes, 29),
                    workspace_generation: get64(bytes, 37),
                    device: get64(bytes, 45),
                    inode: get64(bytes, 53),
                })
            }
            _ => return Err(PublisherDecodeError),
        };
        let setup = Self {
            region_len: get64(bytes, 5),
            process_generation: get64(bytes, 21),
            device_digest_workspace,
            lender_generation: get64(bytes, 61),
            device: get64(bytes, 77),
            inode: get64(bytes, 85),
            producer_event: get64(bytes, 93),
            receiver_event: get64(bytes, 101),
        };
        setup.validate()?;

        Ok(setup)
    }
}

/// Sends one publisher setup frame with its exact eight or nine borrowed roles.
///
/// The optional workspace precedes all three publisher roles. The caller owns
/// role authentication and retains aliases after partial or uncertain delivery.
/// The returned receipt records a completed socket write only.
///
/// # Errors
/// Refuses malformed frames, mismatched roster counts, negative descriptors,
/// non-socket endpoints or ancillary/send failures. A partial send never retries.
#[cfg(unix)]
pub fn send_publisher_setup_frame_with_descriptors(
    socket: std::os::fd::RawFd,
    frame: &[u8; PUBLISHER_SETUP_FRAME_BYTES],
    descriptors: &[std::os::fd::RawFd],
) -> Result<crate::PreexecSetupHandover, crate::DescriptorHandoverError> {
    let refused = || crate::DescriptorHandoverError::MalformedAncillary {
        reason: "publisher pre-exec frame or descriptor roster differs",
    };
    let setup = PublisherSetup::decode(frame).map_err(|_| refused())?;
    let count = 8 + usize::from(setup.device_digest_workspace.is_some());
    if descriptors.len() != count || descriptors.iter().any(|descriptor| *descriptor < 0) {
        return Err(refused());
    }

    let (device, inode) = crate::preexec_socket_identity(socket)?;
    crate::send_frame_with_fds(socket, frame, descriptors)?;

    Ok(crate::PreexecSetupHandover { device, inode })
}
