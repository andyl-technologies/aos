//! Preserves the existing upper API for the sole native R8X proof reader.
//!
//! Cache owns the original fixed-peer/nonce/framing/EOF engine and opaque
//! release evidence. Only its canonical ACK error receives the old upper
//! stale-ACK IO wrapper; all native transport errors move unchanged.

pub use aos_sandbox_cache::RootV8ReleasedProofV1;
use aos_sandbox_model::ObjectDigest;
pub use aos_sandbox_protocol::root_settlement::POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2;
use std::{io, os::unix::net::UnixStream};

fn original_error(cause: aos_sandbox_cache::RootV8ReleasedProofReadErrorV1) -> io::Error {
    match cause {
        aos_sandbox_cache::RootV8ReleasedProofReadErrorV1::Transport(cause) => cause,
        aos_sandbox_cache::RootV8ReleasedProofReadErrorV1::Ack(cause) => {
            io::Error::other(super::RootV8EffectAckErrorV1::from(cause))
        }
    }
}

/// Reads exact released custody from the original fixed root-owned socket.
///
/// # Errors
/// Preserves the original peer, IO, nonce, phase, ACK and EOF refusals.
pub fn read_root_v8_released_proof_v1(
    stream: &mut UnixStream,
    nonce: [u8; 16],
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<Option<RootV8ReleasedProofV1>> {
    aos_sandbox_cache::read_root_v8_released_proof_original_v1(stream, nonce, binding, epoch)
        .map_err(original_error)
}

/// Checks the original untrusted R8X frame without minting release evidence.
///
/// # Errors
/// Preserves the original width, nonce, phase, ACK and encoding refusals.
pub fn validate_untrusted_root_v8_release_reply_frame_v1(
    frame: &[u8],
    nonce: [u8; 16],
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<bool> {
    aos_sandbox_cache::validate_untrusted_root_v8_release_reply_frame_original_v1(
        frame, nonce, binding, epoch,
    )
    .map_err(original_error)
}
