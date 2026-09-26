//! Held Controller-to-Root challenge/receipt exchange for one no-Apply ACK.
//!
//! ```text
//! AOSPHQ6A | client-nonce[16] | reserved[8]=0 | binding[32] | epoch:u64
//! AOSPHC6A | client-nonce[16] | Root-nonce[16] | Root-cut[32]
//! AOSPHS6A | client-nonce[16] | signed Controller AOSCTE01[340] | EOF
//! AOSPHR6A | client-nonce[16] | binding[32] | epoch:u64 |
//! disposition:absent|acknowledged | AOSPCA01[268] | EOF
//! AOSPHQ6R | client-nonce[16] | reserved[8]=0 | binding[32] | epoch:u64 | EOF
//! ```
//!
//! The same authenticated socket lets Root challenge the still-blocked
//! Controller worker; no reverse Controller listener or second writer exists.
//! Every result is nonauthorizing and preserves all owner holds.

use std::io::{self, Read as _, Write as _};
use std::time::Duration;

use aos_sandbox::journal::{ControllerPolicyEffectAckV1, Journal};
use aos_sandbox::policy_compiler::{
    CONTROLLER_EFFECT_ACK_READBACK_BYTES_V1, ControllerEffectAckChallengeV1,
    ROOT_EFFECT_ACK_RECORD_BYTES_V1, RootEffectAckV1, sign_fixed_controller_effect_ack_readback_v1,
};
use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;

use crate::policy_authority_client::connect_policy_query;

/// Starts the held Root effect-ACK challenge exchange.
pub const ROOT_EFFECT_ACK_QUERY_MAGIC_V1: &[u8; 8] = b"AOSPHQ6A";
/// Frames Root's nonce and exact protected cut.
pub const ROOT_EFFECT_ACK_CHALLENGE_MAGIC_V1: &[u8; 8] = b"AOSPHC6A";
/// Submits one signed Controller-only ACK receipt.
pub const ROOT_EFFECT_ACK_SUBMIT_MAGIC_V1: &[u8; 8] = b"AOSPHS6A";
/// Frames Root's durable ACK or explicit absence.
pub const ROOT_EFFECT_ACK_REPLY_MAGIC_V1: &[u8; 8] = b"AOSPHR6A";
/// Replays Root's durable ACK after an ambiguous response.
pub const ROOT_EFFECT_ACK_REPLAY_QUERY_MAGIC_V1: &[u8; 8] = b"AOSPHQ6R";

/// Bounds one Root challenge frame.
pub const ROOT_EFFECT_ACK_CHALLENGE_FRAME_BYTES_V1: usize = 72;
/// Bounds one Controller signed packet submission.
pub const ROOT_EFFECT_ACK_SUBMIT_FRAME_BYTES_V1: usize =
    24 + CONTROLLER_EFFECT_ACK_READBACK_BYTES_V1;
/// Bounds one exact Root ACK or absent replay reply.
pub const ROOT_EFFECT_ACK_REPLY_FRAME_BYTES_V1: usize = 65 + ROOT_EFFECT_ACK_RECORD_BYTES_V1;

const ROOT_WAIT: Duration = Duration::from_secs(45);

/// Encodes a durable Root ACK reply without granting effect authority.
///
/// # Errors
///
/// Rejects malformed claims or a Root record for a different binding/epoch.
pub fn encode_root_effect_ack_reply_v1(
    nonce: [u8; 16],
    binding: ObjectDigest,
    epoch: u64,
    ack: Option<RootEffectAckV1>,
) -> io::Result<[u8; ROOT_EFFECT_ACK_REPLY_FRAME_BYTES_V1]> {
    if nonce == [0; 16] || binding.as_bytes() == &[0; 32] || epoch == 0 {
        return Err(invalid_reply());
    }
    let mut reply = [0; ROOT_EFFECT_ACK_REPLY_FRAME_BYTES_V1];
    reply[..8].copy_from_slice(ROOT_EFFECT_ACK_REPLY_MAGIC_V1);
    reply[8..24].copy_from_slice(&nonce);
    reply[24..56].copy_from_slice(binding.as_bytes());
    reply[56..64].copy_from_slice(&epoch.to_be_bytes());
    if let Some(ack) = ack {
        if ack.binding() != binding || ack.epoch() != epoch {
            return Err(invalid_reply());
        }
        reply[64] = 1;
        reply[65..].copy_from_slice(&ack.record_bytes().map_err(io::Error::other)?);
    }
    Ok(reply)
}

fn decode_root_effect_ack_reply_v1(
    reply: &[u8; ROOT_EFFECT_ACK_REPLY_FRAME_BYTES_V1],
    nonce: [u8; 16],
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<Option<RootEffectAckV1>> {
    if &reply[..8] != ROOT_EFFECT_ACK_REPLY_MAGIC_V1
        || reply[8..24] != nonce
        || reply[24..56] != *binding.as_bytes()
        || reply[56..64] != epoch.to_be_bytes()
    {
        return Err(invalid_reply());
    }
    match reply[64] {
        0 if reply[65..].iter().all(|byte| *byte == 0) => Ok(None),
        1 => {
            let ack = RootEffectAckV1::from_record_bytes(&reply[65..]).map_err(io::Error::other)?;
            if ack.binding() != binding || ack.epoch() != epoch {
                return Err(invalid_reply());
            }
            Ok(Some(ack))
        }
        _ => Err(invalid_reply()),
    }
}

/// Replays the exact Root ACK while Controller and the other owners remain held.
///
/// Absence is not evidence that a previous receipt was rejected; it only
/// reports no durable ACK at the current protected Root head.
///
/// # Errors
///
/// Rejects an unexpected Root peer, stale claim, malformed reply, or timeout.
pub fn recover_held_root_effect_ack_v1(
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<Option<RootEffectAckV1>> {
    let (mut stream, nonce) =
        connect_policy_query(ROOT_EFFECT_ACK_REPLAY_QUERY_MAGIC_V1, ROOT_WAIT)?;
    stream.write_all(binding.as_bytes())?;
    stream.write_all(&epoch.to_be_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    read_root_reply(&mut stream, nonce, binding, epoch)
}

/// Signs Root's spent challenge under the held Controller journal and awaits its ACK.
///
/// The caller must retain Controller, Source, protected Cache, and physical
/// Cache writers around this call. A lost or malformed final response is
/// resolved only by exact Root journal replay under those same holds. No
/// owner is released and no public Create/Apply effect is permitted.
///
/// # Errors
///
/// Rejects stale Controller ACK, changed signer, foreign Root peer or framing,
/// conflicting Root replay, or transport failure with no matching durable ACK.
pub fn acknowledge_held_root_effect_v1(
    controller: &mut Journal,
    expected: ControllerPolicyEffectAckV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> io::Result<RootEffectAckV1> {
    if controller
        .controller_policy_effect_ack_v1()
        .map_err(io::Error::other)?
        != Some(expected)
        || controller
            .controller_policy_hold_v1()
            .map_err(io::Error::other)?
            != Some(expected.hold())
    {
        return Err(invalid_reply());
    }
    let binding = expected.hold().binding();
    let epoch = expected.hold().epoch();
    let (mut stream, nonce) = connect_policy_query(ROOT_EFFECT_ACK_QUERY_MAGIC_V1, ROOT_WAIT)?;
    stream.write_all(binding.as_bytes())?;
    stream.write_all(&epoch.to_be_bytes())?;

    let mut first = [0; 8];
    if let Err(error) = stream.read_exact(&mut first) {
        drop(stream);
        return recover_exact_after_ambiguity(binding, epoch, expected, signer_generation, error);
    }
    let outcome = if &first == ROOT_EFFECT_ACK_REPLY_MAGIC_V1 {
        let mut reply = [0; ROOT_EFFECT_ACK_REPLY_FRAME_BYTES_V1];
        reply[..8].copy_from_slice(&first);
        let received = stream
            .read_exact(&mut reply[8..])
            .and_then(|()| require_eof(&mut stream))
            .and_then(|()| decode_root_effect_ack_reply_v1(&reply, nonce, binding, epoch))
            .and_then(|ack| ack.ok_or_else(invalid_reply));
        match received {
            Ok(ack) => Ok(ack),
            Err(error) => {
                drop(stream);
                recover_exact_after_ambiguity(binding, epoch, expected, signer_generation, error)
            }
        }
    } else if &first == ROOT_EFFECT_ACK_CHALLENGE_MAGIC_V1 {
        let mut challenge_frame = [0; ROOT_EFFECT_ACK_CHALLENGE_FRAME_BYTES_V1];
        challenge_frame[..8].copy_from_slice(&first);
        stream.read_exact(&mut challenge_frame[8..])?;
        if challenge_frame[8..24] != nonce {
            return Err(invalid_reply());
        }
        let challenge = ControllerEffectAckChallengeV1::new(
            challenge_frame[24..40]
                .try_into()
                .map_err(|_| invalid_reply())?,
            ObjectDigest::from_bytes(
                challenge_frame[40..72]
                    .try_into()
                    .map_err(|_| invalid_reply())?,
            ),
        )
        .map_err(io::Error::other)?;
        let packet = sign_fixed_controller_effect_ack_readback_v1(
            controller,
            challenge,
            signer_generation,
            signing_key,
        )
        .map_err(io::Error::other)?;
        let mut submit = [0; ROOT_EFFECT_ACK_SUBMIT_FRAME_BYTES_V1];
        submit[..8].copy_from_slice(ROOT_EFFECT_ACK_SUBMIT_MAGIC_V1);
        submit[8..24].copy_from_slice(&nonce);
        submit[24..].copy_from_slice(&packet);
        let submitted = stream
            .write_all(&submit)
            .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
            .and_then(|()| read_root_reply(&mut stream, nonce, binding, epoch))
            .and_then(|ack| ack.ok_or_else(invalid_reply));
        match submitted {
            Ok(ack) => Ok(ack),
            Err(error) => {
                drop(stream);
                recover_exact_after_ambiguity(binding, epoch, expected, signer_generation, error)
            }
        }
    } else {
        return Err(invalid_reply());
    }?;
    verify_root_ack(outcome, expected, signer_generation)?;
    Ok(outcome)
}

fn recover_exact_after_ambiguity(
    binding: ObjectDigest,
    epoch: u64,
    expected: ControllerPolicyEffectAckV1,
    signer_generation: u64,
    original: io::Error,
) -> io::Result<RootEffectAckV1> {
    match recover_held_root_effect_ack_v1(binding, epoch)? {
        Some(ack) if verify_root_ack(ack, expected, signer_generation).is_ok() => Ok(ack),
        Some(_) => Err(invalid_reply()),
        None => Err(original),
    }
}

fn verify_root_ack(
    ack: RootEffectAckV1,
    expected: ControllerPolicyEffectAckV1,
    signer_generation: u64,
) -> io::Result<()> {
    let hold = expected.hold();
    if ack.binding() != hold.binding()
        || ack.epoch() != hold.epoch()
        || ack.operation() != hold.operation()
        || ack.sandbox() != hold.sandbox()
        || ack.accepted_generation() != expected.accepted_generation()
        || ack.effect_transaction() != expected.effect_transaction()
        || ack.root_proof() != expected.root_proof()
        || ack.controller_ack() != expected.record_digest().map_err(io::Error::other)?
        || ack.signer_generation() != signer_generation
        || ack.controller_uid() != rustix::process::getuid().as_raw()
    {
        return Err(invalid_reply());
    }
    Ok(())
}

fn read_root_reply(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: [u8; 16],
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<Option<RootEffectAckV1>> {
    let mut reply = [0; ROOT_EFFECT_ACK_REPLY_FRAME_BYTES_V1];
    stream.read_exact(&mut reply)?;
    require_eof(stream)?;
    decode_root_effect_ack_reply_v1(&reply, nonce, binding, epoch)
}

fn require_eof(stream: &mut std::os::unix::net::UnixStream) -> io::Result<()> {
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(invalid_reply());
    }
    Ok(())
}

fn invalid_reply() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Root effect acknowledgment",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_ack_frame_rejects_foreign_nonce_and_noncanonical_absence() {
        let binding = ObjectDigest::from_bytes([1; 32]);
        let reply = encode_root_effect_ack_reply_v1([2; 16], binding, 3, None).unwrap();
        assert_eq!(
            decode_root_effect_ack_reply_v1(&reply, [2; 16], binding, 3).unwrap(),
            None
        );
        assert!(decode_root_effect_ack_reply_v1(&reply, [4; 16], binding, 3).is_err());
        let mut altered = reply;
        altered[65] = 1;
        assert!(decode_root_effect_ack_reply_v1(&altered, [2; 16], binding, 3).is_err());
    }

    #[test]
    fn root_ack_reply_timeout_never_becomes_absence() {
        let (mut client, _root) = std::os::unix::net::UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        assert!(
            read_root_reply(&mut client, [2; 16], ObjectDigest::from_bytes([1; 32]), 3).is_err()
        );
    }
}
