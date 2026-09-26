//! Distinct authenticated Controller-to-Root V8 held-ACK exchange.
//!
//! ```text
//! AOSPHQ8A | client-nonce[16] | reserved[8]=0 | binding[32] | epoch:u64
//! AOSPHC8A | client-nonce[16] | Root-nonce[16] | Root-cut[32]
//! AOSPHS8A | client-nonce[16] | signed AOSCTE08[468] | EOF
//! AOSPHR8A | client-nonce[16] | binding[32] | epoch:u64 |
//! disposition:absent|acknowledged | AOSPC88A[332] | EOF
//! AOSPHQ8R | client-nonce[16] | reserved[8]=0 | binding[32] | epoch:u64 | EOF
//! ```
//!
//! Both live and cold paths leave all owner holds intact. An ambiguous live
//! response can return only the exact durable Root row from replay.

use std::io::{self, Read as _, Write as _};
use std::time::Duration;

use aos_sandbox::journal::{ControllerPolicyV8EffectAckV1, Journal};
use aos_sandbox::policy_compiler::{
    CONTROLLER_V8_EFFECT_ACK_READBACK_BYTES_V1, ControllerEffectAckChallengeV1,
    ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1, RootV8EffectAckV1,
    sign_fixed_controller_v8_effect_ack_readback_v1,
};
use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;

use crate::policy_authority_client::connect_policy_query;

/// Starts a live V8 ACK exchange.
pub const ROOT_V8_ACK_QUERY_MAGIC: &[u8; 8] = b"AOSPHQ8A";
/// Carries Root's fresh protected challenge.
pub const ROOT_V8_ACK_CHALLENGE_MAGIC: &[u8; 8] = b"AOSPHC8A";
/// Carries Controller's role-signed ACK packet.
pub const ROOT_V8_ACK_SUBMIT_MAGIC: &[u8; 8] = b"AOSPHS8A";
/// Carries the protected Root ACK or explicit absence.
pub const ROOT_V8_ACK_REPLY_MAGIC: &[u8; 8] = b"AOSPHR8A";
/// Requests historical Root ACK replay.
pub const ROOT_V8_ACK_REPLAY_QUERY_MAGIC: &[u8; 8] = b"AOSPHQ8R";
/// Bounds one Root challenge frame.
pub const ROOT_V8_ACK_CHALLENGE_FRAME_BYTES: usize = 72;
/// Bounds one Controller signed submission frame.
pub const ROOT_V8_ACK_SUBMIT_FRAME_BYTES: usize = 24 + CONTROLLER_V8_EFFECT_ACK_READBACK_BYTES_V1;
/// Bounds one exact Root reply frame.
pub const ROOT_V8_ACK_REPLY_FRAME_BYTES: usize = 65 + ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1;

const ROOT_WAIT: Duration = Duration::from_secs(45);

/// Encodes one protected Root reply without granting release.
///
/// # Errors
///
/// Rejects an empty claim or mismatched durable record.
pub fn encode_root_v8_ack_reply(
    nonce: [u8; 16],
    binding: ObjectDigest,
    epoch: u64,
    ack: Option<RootV8EffectAckV1>,
) -> io::Result<[u8; ROOT_V8_ACK_REPLY_FRAME_BYTES]> {
    if nonce == [0; 16] || binding.as_bytes() == &[0; 32] || epoch == 0 {
        return Err(invalid_reply());
    }
    let mut reply = [0; ROOT_V8_ACK_REPLY_FRAME_BYTES];
    reply[..8].copy_from_slice(ROOT_V8_ACK_REPLY_MAGIC);
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

fn decode_reply(
    reply: &[u8; ROOT_V8_ACK_REPLY_FRAME_BYTES],
    nonce: [u8; 16],
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<Option<RootV8EffectAckV1>> {
    if reply[..8] != *ROOT_V8_ACK_REPLY_MAGIC
        || reply[8..24] != nonce
        || reply[24..56] != *binding.as_bytes()
        || reply[56..64] != epoch.to_be_bytes()
    {
        return Err(invalid_reply());
    }
    match reply[64] {
        0 if reply[65..].iter().all(|byte| *byte == 0) => Ok(None),
        1 => {
            let ack =
                RootV8EffectAckV1::from_record_bytes(&reply[65..]).map_err(io::Error::other)?;
            if ack.binding() != binding || ack.epoch() != epoch {
                return Err(invalid_reply());
            }
            Ok(Some(ack))
        }
        _ => Err(invalid_reply()),
    }
}

/// Replays a historical Root V8 ACK while earlier owner writers remain held.
///
/// Absence cannot prove that a previous submission was rejected.
///
/// # Errors
///
/// Rejects foreign Root peer, malformed framing, or transport loss.
pub fn recover_held_root_v8_ack(
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<Option<RootV8EffectAckV1>> {
    let (mut stream, nonce) = connect_policy_query(ROOT_V8_ACK_REPLAY_QUERY_MAGIC, ROOT_WAIT)?;
    stream.write_all(binding.as_bytes())?;
    stream.write_all(&epoch.to_be_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    read_reply(&mut stream, nonce, binding, epoch)
}

/// Sends the live Controller-only V8 packet and checks exact Root replay.
///
/// The caller must retain Controller, Source, protected Cache, and physical
/// Cache writers throughout this exchange. This returns no release grant.
///
/// # Errors
///
/// Rejects changed Controller custody, stale signer, a foreign Root peer,
/// altered receipt, or ambiguous transport without exact protected replay.
pub fn acknowledge_held_root_v8_effect(
    controller: &mut Journal,
    expected: ControllerPolicyV8EffectAckV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> io::Result<RootV8EffectAckV1> {
    if controller
        .controller_policy_v8_effect_ack_v1()
        .map_err(io::Error::other)?
        != Some(expected)
        || controller
            .controller_policy_v8_attempt_v1()
            .map_err(io::Error::other)?
            != Some(expected.attempt())
        || controller
            .controller_policy_hold_v1()
            .map_err(io::Error::other)?
            != Some(expected.attempt().hold())
    {
        return Err(invalid_reply());
    }
    let binding = expected.attempt().hold().binding();
    let epoch = expected.attempt().hold().epoch();
    let (mut stream, nonce) = connect_policy_query(ROOT_V8_ACK_QUERY_MAGIC, ROOT_WAIT)?;
    stream.write_all(binding.as_bytes())?;
    stream.write_all(&epoch.to_be_bytes())?;

    let mut first = [0; 8];
    let outcome = match stream.read_exact(&mut first) {
        Err(error) => {
            drop(stream);
            return recover_exact_after_ambiguity(
                binding,
                epoch,
                expected,
                signer_generation,
                error,
            );
        }
        Ok(()) if &first == ROOT_V8_ACK_REPLY_MAGIC => {
            let mut reply = [0; ROOT_V8_ACK_REPLY_FRAME_BYTES];
            reply[..8].copy_from_slice(&first);
            stream
                .read_exact(&mut reply[8..])
                .and_then(|()| require_eof(&mut stream))
                .and_then(|()| decode_reply(&reply, nonce, binding, epoch))
                .and_then(|row| row.ok_or_else(invalid_reply))
        }
        Ok(()) if &first == ROOT_V8_ACK_CHALLENGE_MAGIC => {
            let mut frame = [0; ROOT_V8_ACK_CHALLENGE_FRAME_BYTES];
            frame[..8].copy_from_slice(&first);
            stream.read_exact(&mut frame[8..])?;
            if frame[8..24] != nonce {
                return Err(invalid_reply());
            }
            let challenge = ControllerEffectAckChallengeV1::new(
                frame[24..40].try_into().map_err(|_| invalid_reply())?,
                ObjectDigest::from_bytes(frame[40..72].try_into().map_err(|_| invalid_reply())?),
            )
            .map_err(io::Error::other)?;
            let packet = sign_fixed_controller_v8_effect_ack_readback_v1(
                controller,
                challenge,
                signer_generation,
                signing_key,
            )
            .map_err(io::Error::other)?;
            let mut submit = [0; ROOT_V8_ACK_SUBMIT_FRAME_BYTES];
            submit[..8].copy_from_slice(ROOT_V8_ACK_SUBMIT_MAGIC);
            submit[8..24].copy_from_slice(&nonce);
            submit[24..].copy_from_slice(&packet);
            stream
                .write_all(&submit)
                .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
                .and_then(|()| read_reply(&mut stream, nonce, binding, epoch))
                .and_then(|row| row.ok_or_else(invalid_reply))
        }
        Ok(()) => Err(invalid_reply()),
    };
    let row = match outcome {
        Ok(row) => row,
        Err(error) => {
            drop(stream);
            return recover_exact_after_ambiguity(
                binding,
                epoch,
                expected,
                signer_generation,
                error,
            );
        }
    };
    verify_exact(row, expected, signer_generation)?;
    Ok(row)
}

fn recover_exact_after_ambiguity(
    binding: ObjectDigest,
    epoch: u64,
    expected: ControllerPolicyV8EffectAckV1,
    generation: u64,
    original: io::Error,
) -> io::Result<RootV8EffectAckV1> {
    match recover_held_root_v8_ack(binding, epoch)? {
        Some(row) if verify_exact(row, expected, generation).is_ok() => Ok(row),
        Some(_) => Err(invalid_reply()),
        None => Err(original),
    }
}

fn verify_exact(
    row: RootV8EffectAckV1,
    expected: ControllerPolicyV8EffectAckV1,
    generation: u64,
) -> io::Result<()> {
    let hold = expected.attempt().hold();
    if row.binding() != hold.binding()
        || row.epoch() != hold.epoch()
        || row.operation() != hold.operation()
        || row.sandbox() != hold.sandbox()
        || row.accepted_generation() != expected.accepted_generation()
        || row.effect_transaction() != expected.effect_transaction()
        || row.terminal() != expected.attempt().terminal()
        || row.proof() != expected.root_proof()
        || row.quota() != expected.cache_quota()
        || row.controller_ack() != expected.record_digest().map_err(io::Error::other)?
        || row.signer_generation() != generation
        || row.controller_uid() != rustix::process::getuid().as_raw()
    {
        return Err(invalid_reply());
    }
    Ok(())
}

fn read_reply(
    stream: &mut std::os::unix::net::UnixStream,
    nonce: [u8; 16],
    binding: ObjectDigest,
    epoch: u64,
) -> io::Result<Option<RootV8EffectAckV1>> {
    let mut reply = [0; ROOT_V8_ACK_REPLY_FRAME_BYTES];
    stream.read_exact(&mut reply)?;
    require_eof(stream)?;
    decode_reply(&reply, nonce, binding, epoch)
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
        "invalid Root V8 effect acknowledgment",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v8_reply_rejects_foreign_nonce_and_noncanonical_absence() {
        let binding = ObjectDigest::from_bytes([1; 32]);
        let frame = encode_root_v8_ack_reply([2; 16], binding, 3, None).unwrap();
        assert_eq!(decode_reply(&frame, [2; 16], binding, 3).unwrap(), None);
        assert!(decode_reply(&frame, [4; 16], binding, 3).is_err());
        let mut altered = frame;
        altered[65] = 1;
        assert!(decode_reply(&altered, [2; 16], binding, 3).is_err());
    }

    #[test]
    fn v8_reply_timeout_does_not_become_absence() {
        let (mut client, _root) = std::os::unix::net::UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        assert!(read_reply(&mut client, [2; 16], ObjectDigest::from_bytes([1; 32]), 3).is_err());
    }
}
