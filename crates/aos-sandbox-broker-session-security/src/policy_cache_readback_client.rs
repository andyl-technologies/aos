//! Authenticated, nonauthorizing root challenge for a held physical Cache owner.
//!
//! The Controller may request one protected root-writer challenge while its
//! physical Cache owner keeps `.owner.lock`. The response is signed by the
//! separate Cache-purpose key and root only acknowledges verification. This
//! protocol does not join protected Cache quotas, Controller/source heads, or
//! a root CAS, and its result cannot authorize Q04 or public Create.
//!
//! ```text
//! AOSPHQ05 | client-nonce:16 | reserved:8
//! AOSPHB05 | client-nonce:16 | root-nonce:16 | root-source-cut:32 | epoch:u64
//! AOSPHR05 | client-nonce:16 | AOSCRB01 packet:244
//! AOSPHO05 | client-nonce:16 | packet-sha256:32 | epoch:u64
//! ```

use std::io::{self, Read as _, Write as _};
use std::time::Duration;

use aos_sandbox::cache_residency::{
    CLOSED_CACHE_OWNER_READBACK_BYTES_V1, CacheOwnerHeldSnapshotV1, CacheOwnerReadbackChallengeV1,
};
use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::policy_authority_client::connect_policy_query;

/// Selects the closed Cache-owner readback exchange; it never selects Q04.
pub const POLICY_CACHE_READBACK_QUERY_MAGIC_V5: &[u8; 8] = b"AOSPHQ05";
/// Frames one root-generated challenge under its protected writer.
pub const POLICY_CACHE_READBACK_CHALLENGE_MAGIC_V5: &[u8; 8] = b"AOSPHB05";
/// Frames one signed physical owner response.
pub const POLICY_CACHE_READBACK_SUBMIT_MAGIC_V5: &[u8; 8] = b"AOSPHR05";
/// Acknowledges only exact nonauthorizing signature verification.
pub const POLICY_CACHE_READBACK_OBSERVATION_MAGIC_V5: &[u8; 8] = b"AOSPHO05";
/// Bounds the fixed root challenge frame.
pub const CLOSED_CACHE_READBACK_CHALLENGE_FRAME_BYTES_V5: usize = 80;
/// Bounds the fixed Controller response frame.
pub const CLOSED_CACHE_READBACK_SUBMIT_FRAME_BYTES_V5: usize =
    24 + CLOSED_CACHE_OWNER_READBACK_BYTES_V1;
/// Bounds the fixed root observation frame.
pub const CLOSED_CACHE_READBACK_OBSERVATION_FRAME_BYTES_V5: usize = 64;

/// Reports a matched closed readback observation, never an effect token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedCacheReadbackClientObservationV5 {
    packet_digest: ObjectDigest,
    challenge_epoch: u64,
}

impl ClosedCacheReadbackClientObservationV5 {
    /// Returns the exact signed response packet digest.
    #[must_use]
    pub const fn packet_digest(self) -> ObjectDigest {
        self.packet_digest
    }

    /// Returns the root's spent challenge epoch.
    #[must_use]
    pub const fn challenge_epoch(self) -> u64 {
        self.challenge_epoch
    }
}

/// Signs one fresh root challenge with a locally held physical Cache owner.
///
/// The caller must load the distinct seed and generation from fixed protected
/// Controller credentials. Root independently verifies against its fixed
/// `AOSCPK01` pin. Even a successful observation does not prove protected
/// Cache quota currentness or confer publication/effect authority.
///
/// # Errors
///
/// Rejects an unexpected root peer, changed physical root/lock/manifest,
/// malformed or stale framing, signing failure, transport loss, or a missing
/// exact root observation.
pub fn observe_closed_cache_owner_readback_v5(
    snapshot: &CacheOwnerHeldSnapshotV1<'_>,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> io::Result<ClosedCacheReadbackClientObservationV5> {
    let (mut stream, client_nonce) = connect_policy_query(
        POLICY_CACHE_READBACK_QUERY_MAGIC_V5,
        Duration::from_secs(35),
    )?;
    let mut challenge_frame = [0_u8; CLOSED_CACHE_READBACK_CHALLENGE_FRAME_BYTES_V5];
    stream.read_exact(&mut challenge_frame)?;
    let (challenge, epoch) = decode_challenge(&challenge_frame, client_nonce)?;

    snapshot.revalidate().map_err(io::Error::other)?;
    let packet = snapshot
        .sign_closed_readback(challenge, signer_generation, signing_key)
        .map_err(io::Error::other)?;
    snapshot.revalidate().map_err(io::Error::other)?;
    stream.write_all(POLICY_CACHE_READBACK_SUBMIT_MAGIC_V5)?;
    stream.write_all(&client_nonce)?;
    stream.write_all(&packet)?;

    let mut observation_frame = [0_u8; CLOSED_CACHE_READBACK_OBSERVATION_FRAME_BYTES_V5];
    stream.read_exact(&mut observation_frame)?;
    let digest = ObjectDigest::from_bytes(Sha256::digest(packet).into());
    validate_observation(&observation_frame, client_nonce, digest, epoch)?;
    snapshot.revalidate().map_err(io::Error::other)?;
    Ok(ClosedCacheReadbackClientObservationV5 {
        packet_digest: digest,
        challenge_epoch: epoch,
    })
}

fn decode_challenge(
    frame: &[u8; CLOSED_CACHE_READBACK_CHALLENGE_FRAME_BYTES_V5],
    client_nonce: [u8; 16],
) -> io::Result<(CacheOwnerReadbackChallengeV1, u64)> {
    if &frame[..8] != POLICY_CACHE_READBACK_CHALLENGE_MAGIC_V5 || frame[8..24] != client_nonce {
        return Err(invalid_frame());
    }
    let nonce: [u8; 16] = frame[24..40].try_into().map_err(|_| invalid_frame())?;
    let cut = ObjectDigest::from_bytes(frame[40..72].try_into().map_err(|_| invalid_frame())?);
    let epoch = u64::from_be_bytes(frame[72..80].try_into().map_err(|_| invalid_frame())?);
    if epoch == 0 {
        return Err(invalid_frame());
    }
    let challenge = CacheOwnerReadbackChallengeV1::new(nonce, cut).map_err(io::Error::other)?;
    Ok((challenge, epoch))
}

fn validate_observation(
    frame: &[u8; CLOSED_CACHE_READBACK_OBSERVATION_FRAME_BYTES_V5],
    client_nonce: [u8; 16],
    packet_digest: ObjectDigest,
    epoch: u64,
) -> io::Result<()> {
    if &frame[..8] != POLICY_CACHE_READBACK_OBSERVATION_MAGIC_V5
        || frame[8..24] != client_nonce
        || frame[24..56] != *packet_digest.as_bytes()
        || frame[56..64] != epoch.to_be_bytes()
    {
        return Err(invalid_frame());
    }
    Ok(())
}

fn invalid_frame() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid closed Cache readback frame",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_reject_cross_session_nonce_cut_epoch_and_digest() {
        let client_nonce = [3; 16];
        let mut challenge = [0_u8; CLOSED_CACHE_READBACK_CHALLENGE_FRAME_BYTES_V5];
        challenge[..8].copy_from_slice(POLICY_CACHE_READBACK_CHALLENGE_MAGIC_V5);
        challenge[8..24].copy_from_slice(&client_nonce);
        challenge[24..40].copy_from_slice(&[4; 16]);
        challenge[40..72].copy_from_slice(&[5; 32]);
        challenge[72..80].copy_from_slice(&7_u64.to_be_bytes());
        let (decoded, epoch) = decode_challenge(&challenge, client_nonce).expect("fresh frame");
        assert_eq!(decoded.nonce(), [4; 16]);
        assert_eq!(epoch, 7);
        assert!(decode_challenge(&challenge, [9; 16]).is_err());
        challenge[40..72].fill(0);
        assert!(decode_challenge(&challenge, client_nonce).is_err());

        let digest = ObjectDigest::from_bytes([6; 32]);
        let mut observation = [0_u8; CLOSED_CACHE_READBACK_OBSERVATION_FRAME_BYTES_V5];
        observation[..8].copy_from_slice(POLICY_CACHE_READBACK_OBSERVATION_MAGIC_V5);
        observation[8..24].copy_from_slice(&client_nonce);
        observation[24..56].copy_from_slice(digest.as_bytes());
        observation[56..64].copy_from_slice(&7_u64.to_be_bytes());
        assert!(validate_observation(&observation, client_nonce, digest, 7).is_ok());
        assert!(validate_observation(&observation, client_nonce, digest, 8).is_err());
        assert!(validate_observation(&observation, [9; 16], digest, 7).is_err());
        assert!(
            validate_observation(
                &observation,
                client_nonce,
                ObjectDigest::from_bytes([8; 32]),
                7,
            )
            .is_err()
        );
    }
}
