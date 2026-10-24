//! Frames Setup ten with the exact two appended runtime-artifact roles.
//!
//! ```text
//! BEu32(121) | tag0x1a | Setup-nine physical payload and incarnation footer
//! SCM: original eight/nine roles | libc | loader
//! ```
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::RuntimeArtifactDecodeError;
use crate::deferred_cleanup::{DEFERRED_CLEANUP_SETUP_FRAME_BYTES, DeferredCleanupSetup};

/// Describes the proposed ten/eleven-role setup without admitting its profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeArtifactSetup {
    /// Physical publisher roles and the retained dormant delegation incarnation.
    pub cleanup: DeferredCleanupSetup,
}

impl RuntimeArtifactSetup {
    /// Encodes the exact Setup-ten frame while preserving Setup-nine bytes.
    ///
    /// # Errors
    /// Refuses malformed physical observations or unsupported incarnations.
    pub fn encode(
        &self,
    ) -> Result<[u8; DEFERRED_CLEANUP_SETUP_FRAME_BYTES], RuntimeArtifactDecodeError> {
        let mut bytes = self
            .cleanup
            .encode()
            .map_err(|_| RuntimeArtifactDecodeError)?;
        bytes[4] = 0x1a;
        Ok(bytes)
    }

    /// Decodes only Setup ten with its distinct selector.
    ///
    /// # Errors
    /// Refuses every other edition, malformed roles, truncation or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, RuntimeArtifactDecodeError> {
        if bytes.len() != DEFERRED_CLEANUP_SETUP_FRAME_BYTES || bytes[4] != 0x1a {
            return Err(RuntimeArtifactDecodeError);
        }
        let mut cleanup = [0; DEFERRED_CLEANUP_SETUP_FRAME_BYTES];
        cleanup.copy_from_slice(bytes);
        cleanup[4] = 0x19;
        Ok(Self {
            cleanup: DeferredCleanupSetup::decode(&cleanup)
                .map_err(|_| RuntimeArtifactDecodeError)?,
        })
    }
}

/// Sends Setup ten with the exact borrowed roster, ending in libc then loader.
///
/// The two aliases follow all eight or nine existing roles. Actual birth must
/// already retain both immutable aliases; sending observes no loaded mapping
/// and grants no resource, entry permission or profile admission.
///
/// # Errors
/// Refuses malformed/mixed frames, negative descriptors, an incorrect roster,
/// non-socket endpoints and ancillary/send failures. Partial delivery is never
/// retried; the caller retains every actual owner through uncertain delivery.
#[cfg(unix)]
pub fn send_runtime_artifact_setup_frame_with_descriptors(
    socket: std::os::fd::RawFd,
    frame: &[u8; DEFERRED_CLEANUP_SETUP_FRAME_BYTES],
    descriptors: &[std::os::fd::RawFd],
) -> Result<crate::PreexecSetupHandover, crate::DescriptorHandoverError> {
    let refused = || crate::DescriptorHandoverError::MalformedAncillary {
        reason: "runtime-artifact pre-exec frame or descriptor roster differs",
    };
    let setup = RuntimeArtifactSetup::decode(frame).map_err(|_| refused())?;
    let count = 10 + usize::from(setup.cleanup.publisher.device_digest_workspace.is_some());
    if descriptors.len() != count || descriptors.iter().any(|descriptor| *descriptor < 0) {
        return Err(refused());
    }

    let (device, inode) = crate::preexec_socket_identity(socket)?;
    crate::send_frame_with_fds(socket, frame, descriptors)?;
    Ok(crate::PreexecSetupHandover { device, inode })
}
