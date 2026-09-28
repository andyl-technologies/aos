//! Original-monitor controls on the existing protected Host/Guest channel.
//!
//! ```text
//! AOSHCT05 | action:u8 | zero[7] | monitor[32] | request-length:u32 | request
//!          | original-ticket-poll-v3
//! AOSHCR05 | phase:u8 | transfer-attempted:u8 | zero[6] | monitor[32]
//!          | physical/witness/request sections
//!          | Ed25519 signature[64]
//! ```
//!
//! The V3 carrier is reused only for its bounded original ticket, authenticated
//! channel coordinates and narrowed deadlines. A V5 request cannot dispatch V3
//! consume. Neither queue polling nor a signed observation supplies permission:
//! applying a request also requires continuously held current owner cuts.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use crate::openssh_consume::{
    OriginalAttachActionV3, decode_original_attach_request_v3, encode_original_attach_request_v3,
};
use crate::openssh_control::OpenSshControlRequestV5;
use crate::openssh_gate::{OpenSshGateObserveRequestV1, OpenSshGateReadbackErrorV1 as Error};

/// Bounds a complete request or signed response before allocation.
pub const MAXIMUM_ORIGINAL_CONTROL_BYTES_V5: usize = 32 * 1024;

const RESPONSE_DOMAIN: &[u8] = b"aos.sandbox.original-monitor-control-readback.v5\0";

/// Selects queue observation or an exactly committed owner effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalControlActionV5 {
    /// Reads non-authorizing queued data without reserving an effect.
    Poll,
    /// Applies the exact currently queued request through held owner authority.
    Apply,
}

/// Distinguishes queue data from an actual completed Guest effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalControlPhaseV5 {
    /// No control is queued, including absence of live monitor custody.
    Idle,
    /// An original monitor request is queued but has not been authorized here.
    Queued,
    /// The Guest effect and original monitor acknowledgement completed.
    Applied,
}

/// Contains non-authorizing original monitor observations or effect evidence.
pub struct OriginalControlObservationV5 {
    /// Commitment to the actual retained root connection and confined child.
    pub binding: [u8; 32],
    /// Exact queue/effect phase.
    pub phase: OriginalControlPhaseV5,
    /// Records that the original one-use SCM was attempted, possibly ambiguous.
    /// This forbids a second transfer; it does not assert successful I/O or permission.
    pub transfer_attempted: bool,
    /// Original authenticated certificate, holder signature and session witness.
    pub witness: Vec<u8>,
    /// Exact queued or applied request, never a selected execution or process.
    pub request: Vec<u8>,
}

impl std::fmt::Debug for OriginalControlObservationV5 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OriginalControlObservationV5(<redacted>)")
    }
}

/// Encodes a bounded control request without constructing permission.
///
/// # Errors
/// Rejects malformed original ticket/deadlines, substituted poll data, absent
/// apply correlation or a noncanonical control request.
pub fn encode_original_control_request_v5(
    action: OriginalControlActionV5,
    binding: [u8; 32],
    request: &[u8],
    expires_at: i64,
    deadline_boottime_nanoseconds: u64,
    observe: &OpenSshGateObserveRequestV1,
    ticket: &[u8],
) -> Result<Vec<u8>, Error> {
    validate_action(action, binding, request)?;
    let carrier = encode_original_attach_request_v3(
        OriginalAttachActionV3::Poll,
        [0; 32],
        expires_at,
        deadline_boottime_nanoseconds,
        observe,
        ticket,
    )?;
    let mut bytes = b"AOSHCT05".to_vec();
    bytes.push(if action == OriginalControlActionV5::Poll {
        0
    } else {
        1
    });
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(&binding);
    append_section(&mut bytes, request)?;
    bytes.extend_from_slice(&carrier);
    require_bound(&bytes)?;
    Ok(bytes)
}

/// Decodes exact original-ticket control data without authenticating it.
///
/// # Errors
/// Rejects unknown versions/actions, consume carriers, padding, bounds,
/// substituted poll data or malformed control requests.
pub fn decode_original_control_request_v5(
    bytes: &[u8],
) -> Result<
    (
        OriginalControlActionV5,
        [u8; 32],
        &[u8],
        i64,
        u64,
        OpenSshGateObserveRequestV1,
        &[u8],
    ),
    Error,
> {
    require_bound(bytes)?;
    let (code, binding) = decode_header(bytes, b"AOSHCT05")?;
    let action = match code {
        0 => OriginalControlActionV5::Poll,
        1 => OriginalControlActionV5::Apply,
        _ => return Err(Error::InvalidEncoding),
    };
    let (request, carrier) = section(
        &bytes[48..],
        crate::openssh_control::OPENSSH_CONTROL_MAXIMUM_REQUEST_BYTES_V5,
    )?;
    validate_action(action, binding, request)?;
    let (original_action, original_binding, expiry, deadline, observe, ticket) =
        decode_original_attach_request_v3(carrier)?;
    if original_action != OriginalAttachActionV3::Poll || original_binding != [0; 32] {
        return Err(Error::InvalidEncoding);
    }
    Ok((action, binding, request, expiry, deadline, observe, ticket))
}

/// Signs exact queue/effect evidence using the provisioned agent runtime key.
///
/// This is a readback signature, not a grant, certificate or renewed ticket.
///
/// # Errors
/// Rejects inconsistent observations or absent/oversized physical evidence.
pub fn sign_original_control_response_v5(
    observation: &OriginalControlObservationV5,
    physical: &[u8],
    key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    validate_observation(observation)?;
    if physical.is_empty() || physical.len() > crate::openssh_ticket::MAXIMUM_TICKET_GATE_BYTES_V2 {
        return Err(Error::InvalidEncoding);
    }
    let mut bytes = b"AOSHCR05".to_vec();
    bytes.push(match observation.phase {
        OriginalControlPhaseV5::Idle => 0,
        OriginalControlPhaseV5::Queued => 1,
        OriginalControlPhaseV5::Applied => 2,
    });
    bytes.push(u8::from(observation.transfer_attempted));
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&observation.binding);
    for part in [
        physical,
        observation.witness.as_slice(),
        observation.request.as_slice(),
    ] {
        append_section(&mut bytes, part)?;
    }
    let signature = key.sign(&signing_bytes(&bytes));
    bytes.extend_from_slice(&signature.to_bytes());
    require_bound(&bytes)?;
    Ok(bytes)
}

/// Verifies signed bounded evidence without granting current control permission.
///
/// # Errors
/// Rejects invalid signatures, unknown phases, malformed/crossed sections,
/// noncanonical requests or inconsistent observations.
pub fn verify_original_control_response_v5<'a>(
    bytes: &'a [u8],
    key: &VerifyingKey,
) -> Result<(OriginalControlObservationV5, &'a [u8]), Error> {
    require_bound(bytes)?;
    let body_length = bytes.len().checked_sub(64).ok_or(Error::InvalidEncoding)?;
    let (body, signature) = bytes.split_at(body_length);
    let signature = Signature::from_slice(signature).map_err(|_| Error::InvalidEncoding)?;
    key.verify_strict(&signing_bytes(body), &signature)
        .map_err(|_| Error::InvalidEncoding)?;
    decode_response_body(body)
}

/// Decodes canonical signed-packet shape without verifying its signature.
///
/// Only authenticated owner callers may use this cross-link check; this method
/// does not establish Guest provenance or any permission.
///
/// # Errors
/// Rejects truncated/oversized packets, unknown phases or malformed sections.
pub fn decode_original_control_response_shape_v5(
    bytes: &[u8],
) -> Result<(OriginalControlObservationV5, &[u8]), Error> {
    require_bound(bytes)?;
    let length = bytes.len().checked_sub(64).ok_or(Error::InvalidEncoding)?;
    decode_response_body(&bytes[..length])
}

fn decode_response_body(body: &[u8]) -> Result<(OriginalControlObservationV5, &[u8]), Error> {
    if body.len() < 48
        || body.get(..8) != Some(b"AOSHCR05".as_slice())
        || !matches!(body[9], 0 | 1)
        || body[10..16] != [0; 6]
    {
        return Err(Error::InvalidEncoding);
    }
    let (code, binding) = (
        body[8],
        body[16..48]
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?,
    );
    let phase = match code {
        0 => OriginalControlPhaseV5::Idle,
        1 => OriginalControlPhaseV5::Queued,
        2 => OriginalControlPhaseV5::Applied,
        _ => return Err(Error::InvalidEncoding),
    };
    let (physical, rest) = section(
        &body[48..],
        crate::openssh_ticket::MAXIMUM_TICKET_GATE_BYTES_V2,
    )?;
    let (witness, rest) = section(
        rest,
        crate::openssh_monitor::OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2,
    )?;
    let (request, rest) = section(
        rest,
        crate::openssh_control::OPENSSH_CONTROL_MAXIMUM_REQUEST_BYTES_V5,
    )?;
    if physical.is_empty() || !rest.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    let observation = OriginalControlObservationV5 {
        binding,
        phase,
        transfer_attempted: body[9] == 1,
        witness: witness.to_vec(),
        request: request.to_vec(),
    };
    validate_observation(&observation)?;
    Ok((observation, physical))
}

fn validate_action(
    action: OriginalControlActionV5,
    binding: [u8; 32],
    request: &[u8],
) -> Result<(), Error> {
    match action {
        OriginalControlActionV5::Poll if binding == [0; 32] && request.is_empty() => Ok(()),
        OriginalControlActionV5::Apply if binding != [0; 32] => {
            OpenSshControlRequestV5::decode(request)
                .map(|_| ())
                .map_err(|_| Error::InvalidEncoding)
        }
        _ => Err(Error::InvalidEncoding),
    }
}

fn validate_observation(observation: &OriginalControlObservationV5) -> Result<(), Error> {
    if observation.binding == [0; 32] {
        return if observation.phase == OriginalControlPhaseV5::Idle
            && !observation.transfer_attempted
            && observation.witness.is_empty()
            && observation.request.is_empty()
        {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        };
    }
    crate::openssh_monitor::OpenSshMonitorWitnessV2::decode_confined_v3(&observation.witness)
        .map_err(|_| Error::InvalidEncoding)?;
    match observation.phase {
        OriginalControlPhaseV5::Idle if observation.request.is_empty() => Ok(()),
        OriginalControlPhaseV5::Queued | OriginalControlPhaseV5::Applied => {
            OpenSshControlRequestV5::decode(&observation.request)
                .map(|_| ())
                .map_err(|_| Error::InvalidEncoding)
        }
        _ => Err(Error::InvalidEncoding),
    }
}

fn require_bound(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAXIMUM_ORIGINAL_CONTROL_BYTES_V5 {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}

fn decode_header(bytes: &[u8], magic: &[u8; 8]) -> Result<(u8, [u8; 32]), Error> {
    if bytes.len() < 48 || bytes.get(..8) != Some(magic.as_slice()) || bytes[9..16] != [0; 7] {
        return Err(Error::InvalidEncoding);
    }
    Ok((
        bytes[8],
        bytes[16..48]
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?,
    ))
}

fn append_section(bytes: &mut Vec<u8>, part: &[u8]) -> Result<(), Error> {
    bytes.extend_from_slice(
        &u32::try_from(part.len())
            .map_err(|_| Error::InvalidEncoding)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(part);
    Ok(())
}

fn section(bytes: &[u8], maximum: usize) -> Result<(&[u8], &[u8]), Error> {
    let length = u32::from_be_bytes(
        bytes
            .get(..4)
            .and_then(|part| part.try_into().ok())
            .ok_or(Error::InvalidEncoding)?,
    ) as usize;
    if length > maximum {
        return Err(Error::InvalidEncoding);
    }
    let end = 4usize.checked_add(length).ok_or(Error::InvalidEncoding)?;
    Ok((
        bytes.get(4..end).ok_or(Error::InvalidEncoding)?,
        bytes.get(end..).ok_or(Error::InvalidEncoding)?,
    ))
}

fn signing_bytes(body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(RESPONSE_DOMAIN.len() + body.len());
    bytes.extend_from_slice(RESPONSE_DOMAIN);
    bytes.extend_from_slice(body);
    bytes
}

#[cfg(test)]
mod tests {
    //! Canonical framing/signatures only; shaped witnesses are not SSH authority.

    use super::*;
    use crate::openssh_control::{OpenSshControlActionV5, OpenSshPtyGeometryV5};
    use crate::openssh_gate::OpenSshGateBindingV1;

    fn fixture() -> (Vec<u8>, OpenSshGateObserveRequestV1, Vec<u8>) {
        let mut grant = [0; 416];
        grant[..8].copy_from_slice(b"AOSAPG01");
        grant[8..24].copy_from_slice(&[1; 16]);
        grant[24..40].copy_from_slice(&[2; 16]);
        let ticket = aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2 {
            operation_id: [1; 16],
            execution_id: [2; 16],
            incarnation_id: [3; 16],
            principal_id: [4; 16],
            audit_id: [5; 16],
            assignment_epoch: 1,
            valid_after: 10,
            expires_at: 40,
            holder_public_key: [6; 32],
            request_digest: [7; 32],
            decision_digest: [8; 32],
            pending_grant: grant,
            base_route_digest: [9; 32],
            certificate: b"shaped-test-not-a-certificate".to_vec(),
        }
        .encode()
        .unwrap();
        let observe = OpenSshGateObserveRequestV1 {
            session_binding: [10; 32],
            challenge: [11; 32],
            route_digest: [9; 32],
            binding: OpenSshGateBindingV1 {
                attach_operation_id: [1; 16],
                execution_id: [2; 16],
                incarnation_id: [3; 16],
                assignment_epoch: 1,
                principal_id: [4; 16],
                audit_id: [5; 16],
                user: "aos_exec".to_owned(),
                port: 2222,
                host_public_key: "ssh-ed25519 AAAA".to_owned(),
                trusted_user_ca_public_key: "ssh-ed25519 BBBB".to_owned(),
                expires_at: 40,
                gate_config_digest: [12; 32],
            },
        };
        let mut witness = b"AOSAMR03".to_vec();
        witness.extend_from_slice(&1001u32.to_be_bytes());
        witness.extend_from_slice(&1001u32.to_be_bytes());
        for part in [
            [13; 32].as_slice(),
            b"shaped-test-not-a-certificate",
            b"not-a-userauth-message",
            [14; 64].as_slice(),
        ] {
            append_section(&mut witness, part).unwrap();
        }
        (ticket, observe, witness)
    }

    #[test]
    fn all_actions_preserve_exact_request_and_original_deadlines() {
        let (ticket, observe, _) = fixture();
        let geometry = OpenSshPtyGeometryV5 {
            rows: 24,
            columns: 80,
            xpixel: 640,
            ypixel: 480,
        };
        let actions = [
            OpenSshControlActionV5::Signal(15),
            OpenSshControlActionV5::Resize(geometry),
            OpenSshControlActionV5::Pty {
                geometry,
                terminal: "xterm".to_owned(),
                modes: vec![0],
            },
        ];
        for action in actions {
            let request = OpenSshControlRequestV5 {
                sequence: 7,
                action,
            }
            .encode()
            .unwrap();
            let packet = encode_original_control_request_v5(
                OriginalControlActionV5::Apply,
                [15; 32],
                &request,
                30,
                12345,
                &observe,
                &ticket,
            )
            .unwrap();
            let decoded = decode_original_control_request_v5(&packet).unwrap();
            assert_eq!(decoded.0, OriginalControlActionV5::Apply);
            assert_eq!(decoded.1, [15; 32]);
            assert_eq!(decoded.2, request);
            assert_eq!((decoded.3, decoded.4), (30, 12345));
            assert_eq!(decoded.5, observe);
            assert_eq!(decoded.6, ticket);
            for length in 0..packet.len() {
                assert!(decode_original_control_request_v5(&packet[..length]).is_err());
            }
            for index in [0, 8, 9, 15, 48, 51] {
                let mut changed = packet.clone();
                changed[index] ^= 0xff;
                assert!(decode_original_control_request_v5(&changed).is_err());
            }
            let mut trailing = packet;
            trailing.push(0);
            assert!(decode_original_control_request_v5(&trailing).is_err());
        }
        for expiry in [0, 10, 41] {
            assert!(
                encode_original_control_request_v5(
                    OriginalControlActionV5::Poll,
                    [0; 32],
                    &[],
                    expiry,
                    12345,
                    &observe,
                    &ticket
                )
                .is_err()
            );
        }
        assert!(
            encode_original_control_request_v5(
                OriginalControlActionV5::Poll,
                [1; 32],
                &[],
                30,
                12345,
                &observe,
                &ticket
            )
            .is_err()
        );
        assert!(
            encode_original_control_request_v5(
                OriginalControlActionV5::Poll,
                [0; 32],
                &[1],
                30,
                12345,
                &observe,
                &ticket
            )
            .is_err()
        );
    }

    #[test]
    fn control_carrier_cannot_dispatch_a_v3_consume() {
        let (ticket, observe, _) = fixture();
        let mut packet = b"AOSHCT05".to_vec();
        packet.extend_from_slice(&[0; 40]);
        append_section(&mut packet, &[]).unwrap();
        packet.extend_from_slice(
            &encode_original_attach_request_v3(
                OriginalAttachActionV3::Consume,
                [16; 32],
                30,
                12345,
                &observe,
                &ticket,
            )
            .unwrap(),
        );
        assert!(decode_original_control_request_v5(&packet).is_err());
    }

    #[test]
    fn signed_queue_and_completion_reject_foreign_or_substituted_packets() {
        let (_, _, witness) = fixture();
        let key = SigningKey::from_bytes(&[17; 32]);
        let foreign = SigningKey::from_bytes(&[18; 32]);
        let request = OpenSshControlRequestV5 {
            sequence: 3,
            action: OpenSshControlActionV5::Signal(9),
        }
        .encode()
        .unwrap();
        for phase in [
            OriginalControlPhaseV5::Queued,
            OriginalControlPhaseV5::Applied,
        ] {
            let observation = OriginalControlObservationV5 {
                binding: [19; 32],
                phase,
                transfer_attempted: true,
                witness: witness.clone(),
                request: request.clone(),
            };
            let packet =
                sign_original_control_response_v5(&observation, b"physical-shape-only", &key)
                    .unwrap();
            let (decoded, physical) =
                verify_original_control_response_v5(&packet, &key.verifying_key()).unwrap();
            assert_eq!(decoded.phase, phase);
            assert!(decoded.transfer_attempted);
            assert_eq!(decoded.binding, [19; 32]);
            assert_eq!(decoded.request, request);
            assert_eq!(physical, b"physical-shape-only");
            assert!(
                verify_original_control_response_v5(&packet, &foreign.verifying_key()).is_err()
            );
            for index in 0..packet.len() {
                let mut changed = packet.clone();
                changed[index] ^= 1;
                assert!(
                    verify_original_control_response_v5(&changed, &key.verifying_key()).is_err()
                );
            }
            for length in 0..packet.len() {
                assert!(
                    verify_original_control_response_v5(&packet[..length], &key.verifying_key())
                        .is_err()
                );
            }
            let mut changed_signature = packet;
            let last = changed_signature.len() - 1;
            changed_signature[last] ^= 1;
            assert!(decode_original_control_response_shape_v5(&changed_signature).is_ok());
            assert!(
                verify_original_control_response_v5(&changed_signature, &key.verifying_key())
                    .is_err()
            );
        }
    }

    #[test]
    fn cold_idle_and_agent_versions_cannot_mint_control_or_io() {
        let key = SigningKey::from_bytes(&[20; 32]);
        let idle = OriginalControlObservationV5 {
            binding: [0; 32],
            phase: OriginalControlPhaseV5::Idle,
            transfer_attempted: false,
            witness: Vec::new(),
            request: Vec::new(),
        };
        let packet =
            sign_original_control_response_v5(&idle, b"physical-shape-only", &key).unwrap();
        let (decoded, _) =
            verify_original_control_response_v5(&packet, &key.verifying_key()).unwrap();
        assert_eq!(decoded.phase, OriginalControlPhaseV5::Idle);
        assert!(!decoded.transfer_attempted);
        for frame in [
            crate::AgentFrameV1::OriginalControlRequestV5(vec![1]),
            crate::AgentFrameV1::OriginalControlResponseV5(packet),
        ] {
            let bytes = crate::encode_frame_v1(&frame);
            assert_eq!(crate::decode_frame_v1(&bytes).unwrap(), frame);
            let mut unknown = bytes;
            unknown[8] = 14;
            assert!(crate::decode_frame_v1(&unknown).is_err());
        }
    }
}
