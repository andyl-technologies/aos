//! Opaque released-Root evidence from the versioned, peer-checked R8X reply.
//!
//! ```text
//! AOSPHR8X | client-nonce[16] | binding[32] | epoch:u64 |
//! phase:absent|held|released | AOSPC88A[332] |
//! AOSPC88T-digest[32] | AOSPC88L-digest[32] | EOF
//! ```
//!
//! Only a root-peer socket can mint this value. It is not a public Create or
//! Apply grant; callers must still compare the exact Controller and Cache cut.

use std::io::{self, Read as _};
use std::os::unix::net::UnixStream;
use std::path::Path;

use aos_sandbox_core::ObjectDigest;

use crate::journal::{ControllerPolicyV8EffectAckV1, v8_root_receipt_matches_ack};

use super::{ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1, RootV8EffectAckV1};

const REPLY_MAGIC: &[u8; 8] = b"AOSPHR8X";
const REPLY_BYTES: usize = 129 + ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1;

/// Names the sole Root authority socket allowed to mint released evidence.
pub const POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2: &str =
    "/run/aos/sandbox-policy-authority/current-head.sock";

/// Retains a released Root terminal and the replay-validated AOSPC88L digest.
///
/// Its fields are private so a successful no-op callback cannot retire Cache.
/// The proof authenticates Root's socket peer and exact reply framing, but it
/// does not assert that Source, Controller, or Cache has been released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootV8ReleasedProofV1 {
    ack: RootV8EffectAckV1,
    terminal_digest: ObjectDigest,
    release_marker_digest: ObjectDigest,
}

impl RootV8ReleasedProofV1 {
    /// Returns the exact durable Root ACK.
    #[must_use]
    pub const fn ack(self) -> RootV8EffectAckV1 {
        self.ack
    }

    /// Returns the canonical AOSPC88T row digest.
    #[must_use]
    pub const fn terminal_digest(self) -> ObjectDigest {
        self.terminal_digest
    }

    /// Returns the canonical, replay-validated AOSPC88L row digest.
    #[must_use]
    pub const fn release_marker_digest(self) -> ObjectDigest {
        self.release_marker_digest
    }

    /// Compares Root's exact released claim to Controller's durable ACK.
    #[must_use]
    pub fn matches_controller_ack(
        self,
        expected: ControllerPolicyV8EffectAckV1,
        controller_uid: u32,
    ) -> bool {
        self.ack.controller_uid() == controller_uid
            && v8_root_receipt_matches_ack(self.ack, expected).unwrap_or(false)
    }
}

/// Reads an exact released reply from a root-owned Unix socket.
///
/// An absent or still-held phase returns `None`; it never grants Cache
/// retirement. The caller must have connected the fixed policy-authority
/// socket and must compare the returned proof to its protected Controller cut.
///
/// # Errors
///
/// Rejects a non-root peer, changed claim or nonce, malformed phase/digest
/// combination, noncanonical Root ACK, transport timeout, or trailing bytes.
pub fn read_root_v8_released_proof_v1(
    stream: &mut UnixStream,
    nonce: [u8; 16],
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<Option<RootV8ReleasedProofV1>> {
    let peer = rustix::net::sockopt::socket_peercred(&*stream)?;
    if !peer.uid.is_root()
        || stream.peer_addr()?.as_pathname()
            != Some(Path::new(POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2))
    {
        return Err(invalid_reply());
    }
    let mut frame = [0; REPLY_BYTES];
    stream.read_exact(&mut frame)?;
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(invalid_reply());
    }
    decode_reply(&frame, nonce, binding, epoch)
}

/// Validates an untrusted R8X frame without granting Root release custody.
///
/// This pure wire check shares the production decoder so a server can test
/// cross-crate frame compatibility. `true` means that the bytes claim a
/// released phase; only [`read_root_v8_released_proof_v1`] authenticates the
/// fixed Root socket and may produce release evidence.
///
/// # Errors
///
/// Rejects a wrong frame length, version, nonce, claim, phase, or encoding.
pub fn validate_untrusted_root_v8_release_reply_frame_v1(
    frame: &[u8],
    nonce: [u8; 16],
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<bool> {
    let exact: &[u8; REPLY_BYTES] = frame.try_into().map_err(|_| invalid_reply())?;
    decode_reply(exact, nonce, binding, epoch).map(|proof| proof.is_some())
}

fn decode_reply(
    frame: &[u8; REPLY_BYTES],
    nonce: [u8; 16],
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<Option<RootV8ReleasedProofV1>> {
    if nonce == [0; 16]
        || binding.as_bytes() == &[0; 32]
        || epoch == 0
        || frame[..8] != REPLY_MAGIC[..]
        || frame[8..24] != nonce
        || frame[24..56] != *binding.as_bytes()
        || frame[56..64] != epoch.to_be_bytes()
    {
        return Err(invalid_reply());
    }
    match frame[64] {
        0 if frame[65..].iter().all(|byte| *byte == 0) => Ok(None),
        1 if frame[429..461] == [0; 32] => {
            let _ = decode_ack_and_terminal(frame, binding, epoch)?;
            Ok(None)
        }
        2 if frame[429..461] != [0; 32] => {
            let (ack, terminal_digest) = decode_ack_and_terminal(frame, binding, epoch)?;
            let release_marker_digest =
                ObjectDigest::from_bytes(frame[429..461].try_into().map_err(|_| invalid_reply())?);
            Ok(Some(RootV8ReleasedProofV1 {
                ack,
                terminal_digest,
                release_marker_digest,
            }))
        }
        _ => Err(invalid_reply()),
    }
}

fn decode_ack_and_terminal(
    frame: &[u8; REPLY_BYTES],
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<(RootV8EffectAckV1, ObjectDigest)> {
    if frame[397..429] == [0; 32] {
        return Err(invalid_reply());
    }
    let ack = RootV8EffectAckV1::from_record_bytes(&frame[65..397]).map_err(io::Error::other)?;
    if ack.binding() != binding || ack.epoch() != epoch {
        return Err(invalid_reply());
    }
    let terminal_digest =
        ObjectDigest::from_bytes(frame[397..429].try_into().map_err(|_| invalid_reply())?);
    Ok((ack, terminal_digest))
}

fn invalid_reply() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Root V8 released proof")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn sample_ack() -> RootV8EffectAckV1 {
        let mut bytes = [1; ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSPC88A");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10..16].fill(0);
        bytes[48..56].copy_from_slice(&3_u64.to_be_bytes());
        bytes[88..96].copy_from_slice(&4_u64.to_be_bytes());
        bytes[272..280].copy_from_slice(&5_u64.to_be_bytes());
        bytes[280..284].copy_from_slice(&1000_u32.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.policy-compiler.root-v8-effect-ack.v1\0")
            .chain_update(&bytes[..300])
            .finalize();
        bytes[300..].copy_from_slice(&checksum);
        RootV8EffectAckV1::from_record_bytes(&bytes).unwrap()
    }

    fn released_frame(marker: u8) -> [u8; REPLY_BYTES] {
        let ack = sample_ack();
        let mut frame = [0; REPLY_BYTES];
        frame[..8].copy_from_slice(REPLY_MAGIC);
        frame[8..24].fill(2);
        frame[24..56].copy_from_slice(ack.binding().as_bytes());
        frame[56..64].copy_from_slice(&ack.epoch().to_be_bytes());
        frame[64] = 2;
        frame[65..397].copy_from_slice(&ack.record_bytes().unwrap());
        frame[397..429].fill(3);
        frame[429..461].fill(marker);
        frame
    }

    #[test]
    fn released_proof_requires_exact_phase_and_marker_on_replay() {
        let ack = sample_ack();
        let frame = released_frame(4);
        let proof = decode_reply(&frame, [2; 16], ack.binding(), ack.epoch())
            .unwrap()
            .unwrap();
        assert_eq!(proof.ack(), ack);
        assert_eq!(
            proof.release_marker_digest(),
            ObjectDigest::from_bytes([4; 32])
        );
        assert_ne!(
            Some(proof),
            decode_reply(&released_frame(5), [2; 16], ack.binding(), ack.epoch()).unwrap()
        );

        let mut missing = frame;
        missing[429..461].fill(0);
        assert!(decode_reply(&missing, [2; 16], ack.binding(), ack.epoch()).is_err());
        let mut held_with_marker = frame;
        held_with_marker[64] = 1;
        assert!(decode_reply(&held_with_marker, [2; 16], ack.binding(), ack.epoch()).is_err());
        let mut old_version = frame;
        old_version[..8].copy_from_slice(b"AOSPHR8V");
        assert!(decode_reply(&old_version, [2; 16], ack.binding(), ack.epoch()).is_err());
    }

    #[test]
    fn non_root_socket_cannot_mint_a_cache_release_proof() {
        if rustix::process::getuid().is_root() {
            return;
        }
        let ack = sample_ack();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        std::io::Write::write_all(&mut server, &released_frame(4)).unwrap();
        server.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(
            read_root_v8_released_proof_v1(&mut client, [2; 16], ack.binding(), ack.epoch(),)
                .is_err()
        );
    }
}
