//! Sends the separately selected Setup-twelve native-profile descriptor roster.
//!
//! ```text
//! selector "12" (negotiated separately)
//! BEu32(121) | tag0x1a | Setup-ten payload and incarnation footer
//! SCM: existing eight/nine roles | libc | loader | transfer | manifest | probe
//! ```
//!
//! The frame intentionally has the same bytes as Setup ten. The negotiated
//! selector and exact thirteen/fourteen-role roster distinguish this edition;
//! the frame alone cannot establish which edition was selected. This sender
//! does not negotiate the selector or activate a receiving profile.
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(unix)]
use crate::deferred_cleanup::DEFERRED_CLEANUP_SETUP_FRAME_BYTES;
#[cfg(unix)]
use crate::runtime_artifact::RuntimeArtifactSetup;

/// Sends the exact Setup-twelve roster after separate selector negotiation.
///
/// The caller must already retain the immutable libc, loader, transfer,
/// complete manifest and probe aliases, in that order after the original
/// eight/nine roles. Authenticating their bytes, seals, distinct physical
/// identities and agreement with plan fifteen belongs to the actual retained
/// owners. This transport receipt proves only a completed socket write.
///
/// # Errors
/// Refuses malformed framing, an incorrect roster, negative or repeated descriptors,
/// non-socket endpoints and ancillary/send failures. Partial delivery is never
/// retried; the caller retains every owner and delivery uncertainty.
#[cfg(unix)]
pub fn send_native_profile_setup_frame_with_descriptors(
    socket: std::os::fd::RawFd,
    frame: &[u8; DEFERRED_CLEANUP_SETUP_FRAME_BYTES],
    descriptors: &[std::os::fd::RawFd],
) -> Result<crate::PreexecSetupHandover, crate::DescriptorHandoverError> {
    let refused = || crate::DescriptorHandoverError::MalformedAncillary {
        reason: "native-profile pre-exec frame or descriptor roster differs",
    };
    let setup = RuntimeArtifactSetup::decode(frame).map_err(|_| refused())?;
    let count = 13 + usize::from(setup.cleanup.publisher.device_digest_workspace.is_some());
    if descriptors.len() != count
        || descriptors
            .iter()
            .enumerate()
            .any(|(index, descriptor)| *descriptor < 0 || descriptors[..index].contains(descriptor))
    {
        return Err(refused());
    }

    let (device, inode) = crate::preexec_socket_identity(socket)?;
    crate::send_frame_with_fds(socket, frame, descriptors)?;

    Ok(crate::PreexecSetupHandover { device, inode })
}
