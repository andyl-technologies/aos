//! Bounded original-ticket polling and held consume on the existing agent channel.
//!
//! ```text
//! AOSACO03 | action:u8 | reserved[7] | custody[32] | authority_expiry:i64
//!         | effect_boottime_deadline:u64 | ticket_gate_request_v2
//! AOSACR03 | phase:u8  | reserved[7] | custody[32] | physical_length:u32
//!         | signed_ticket_readback_v2 | witness_length:u32 | original_witness
//! ```
//!
//! Polling is not authorization. Consume is accepted only on the provisioned
//! root channel and must join the live monitor/relay handles, immutable ticket,
//! protected process and a durable one-use reservation under the Guest barrier.

use crate::openssh_gate::{OpenSshGateObserveRequestV1, OpenSshGateReadbackErrorV1 as Error};
use crate::openssh_ticket::{decode_ticket_gate_request_v2, encode_ticket_gate_request_v2};

/// Bounds a complete poll/consume request or response before allocation.
pub const MAXIMUM_CONSUME_BYTES_V3: usize = 32 * 1024;

/// Selects the closed original-ticket actions; neither issues a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalAttachActionV3 {
    /// Reads current live custody without reserving or transferring I/O.
    Poll,
    /// Consumes the same original ticket under continuously held owner cuts.
    Consume,
}

/// Describes a live custody observation or a completed descriptor transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalAttachPhaseV3 {
    /// No complete live monitor/relay join is currently held.
    Pending,
    /// The original authenticated ticket and confined relay are held in memory.
    Ready,
    /// One-use transfer and the relay's receipt acknowledgement completed.
    Transferred,
}

/// Carries non-authorizing live observations on the existing protected channel.
pub struct OriginalAttachObservationV3 {
    /// Non-authorizing commitment to the live retained kernel custody record.
    pub binding: [u8; 32],
    /// Exact phase, never a generic boolean authorization flag.
    pub phase: OriginalAttachPhaseV3,
    /// Original monitor certificate/key/session holder-signature witness.
    pub witness: Vec<u8>,
}

impl std::fmt::Debug for OriginalAttachObservationV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OriginalAttachObservationV3(<redacted>)")
    }
}

/// Encodes one exact original-ticket poll or consume.
///
/// # Errors
/// Rejects missing consume correlation, poll substitution, or invalid base data.
pub fn encode_original_attach_request_v3(
    action: OriginalAttachActionV3,
    binding: [u8; 32],
    authority_expires_at: i64,
    effect_deadline_boottime_nanoseconds: u64,
    observe: &OpenSshGateObserveRequestV1,
    ticket: &[u8],
) -> Result<Vec<u8>, Error> {
    validate_action(action, binding)?;
    validate_expiry(authority_expires_at, ticket)?;
    if effect_deadline_boottime_nanoseconds == 0 {
        return Err(Error::InvalidEncoding);
    }
    let mut bytes = b"AOSACO03".to_vec();
    bytes.push(match action {
        OriginalAttachActionV3::Poll => 1,
        OriginalAttachActionV3::Consume => 2,
    });
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(&binding);
    bytes.extend_from_slice(&authority_expires_at.to_be_bytes());
    bytes.extend_from_slice(&effect_deadline_boottime_nanoseconds.to_be_bytes());
    bytes.extend_from_slice(&encode_ticket_gate_request_v2(observe, ticket)?);
    Ok(bytes)
}

/// Decodes exact bounded data without authorizing a consume.
///
/// # Errors
/// Rejects unknown actions, padding, bounds, or noncanonical original data.
pub fn decode_original_attach_request_v3(
    bytes: &[u8],
) -> Result<
    (
        OriginalAttachActionV3,
        [u8; 32],
        i64,
        u64,
        OpenSshGateObserveRequestV1,
        &[u8],
    ),
    Error,
> {
    if bytes.len() > MAXIMUM_CONSUME_BYTES_V3
        || bytes.get(..8) != Some(b"AOSACO03".as_slice())
        || bytes.get(9..16) != Some([0; 7].as_slice())
    {
        return Err(Error::InvalidEncoding);
    }
    let action = match bytes.get(8) {
        Some(1) => OriginalAttachActionV3::Poll,
        Some(2) => OriginalAttachActionV3::Consume,
        _ => return Err(Error::InvalidEncoding),
    };
    let binding = bytes
        .get(16..48)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::InvalidEncoding)?;
    validate_action(action, binding)?;
    let authority_expires_at = i64::from_be_bytes(
        bytes
            .get(48..56)
            .and_then(|value| value.try_into().ok())
            .ok_or(Error::InvalidEncoding)?,
    );
    let effect_deadline_boottime_nanoseconds = u64::from_be_bytes(
        bytes
            .get(56..64)
            .and_then(|value| value.try_into().ok())
            .ok_or(Error::InvalidEncoding)?,
    );
    if effect_deadline_boottime_nanoseconds == 0 {
        return Err(Error::InvalidEncoding);
    }
    let (observe, ticket) =
        decode_ticket_gate_request_v2(bytes.get(64..).ok_or(Error::InvalidEncoding)?)?;
    validate_expiry(authority_expires_at, ticket)?;
    Ok((
        action,
        binding,
        authority_expires_at,
        effect_deadline_boottime_nanoseconds,
        observe,
        ticket,
    ))
}

/// Encodes current custody with the existing signed physical readback packet.
///
/// # Errors
/// Rejects inconsistent phases, missing evidence, and oversized responses.
pub fn encode_original_attach_response_v3(
    observation: &OriginalAttachObservationV3,
    physical: &[u8],
) -> Result<Vec<u8>, Error> {
    validate_observation(observation)?;
    if physical.is_empty() || physical.len() > crate::openssh_ticket::MAXIMUM_TICKET_GATE_BYTES_V2 {
        return Err(Error::InvalidEncoding);
    }
    let mut bytes = b"AOSACR03".to_vec();
    bytes.push(match observation.phase {
        OriginalAttachPhaseV3::Pending => 0,
        OriginalAttachPhaseV3::Ready => 1,
        OriginalAttachPhaseV3::Transferred => 2,
    });
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(&observation.binding);
    for section in [physical, observation.witness.as_slice()] {
        bytes.extend_from_slice(
            &u32::try_from(section.len())
                .map_err(|_| Error::InvalidEncoding)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(section);
    }
    if bytes.len() > MAXIMUM_CONSUME_BYTES_V3 {
        return Err(Error::InvalidEncoding);
    }
    Ok(bytes)
}

/// Decodes bounded transport evidence without promoting it to current authority.
///
/// # Errors
/// Rejects unknown phases, malformed sections, inconsistent evidence or trailing data.
pub fn decode_original_attach_response_v3(
    bytes: &[u8],
) -> Result<(OriginalAttachObservationV3, &[u8]), Error> {
    if bytes.len() > MAXIMUM_CONSUME_BYTES_V3
        || bytes.get(..8) != Some(b"AOSACR03".as_slice())
        || bytes.get(9..16) != Some([0; 7].as_slice())
    {
        return Err(Error::InvalidEncoding);
    }
    let phase = match bytes.get(8) {
        Some(0) => OriginalAttachPhaseV3::Pending,
        Some(1) => OriginalAttachPhaseV3::Ready,
        Some(2) => OriginalAttachPhaseV3::Transferred,
        _ => return Err(Error::InvalidEncoding),
    };
    let binding = bytes
        .get(16..48)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::InvalidEncoding)?;
    let (physical, rest) = section(
        bytes.get(48..).ok_or(Error::InvalidEncoding)?,
        crate::openssh_ticket::MAXIMUM_TICKET_GATE_BYTES_V2,
    )?;
    let (witness, rest) = section(
        rest,
        crate::openssh_monitor::OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2,
    )?;
    if physical.is_empty() || !rest.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    let observation = OriginalAttachObservationV3 {
        binding,
        phase,
        witness: witness.to_vec(),
    };
    validate_observation(&observation)?;
    Ok((observation, physical))
}

fn validate_action(action: OriginalAttachActionV3, binding: [u8; 32]) -> Result<(), Error> {
    if (action == OriginalAttachActionV3::Poll) != (binding == [0; 32]) {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}

fn validate_expiry(authority_expires_at: i64, ticket: &[u8]) -> Result<(), Error> {
    let ticket =
        aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2::decode(ticket)
            .map_err(|_| Error::InvalidEncoding)?;
    let expiry = u64::try_from(authority_expires_at).map_err(|_| Error::InvalidEncoding)?;
    if expiry <= ticket.valid_after || expiry > ticket.expires_at {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}

fn validate_observation(observation: &OriginalAttachObservationV3) -> Result<(), Error> {
    match observation.phase {
        OriginalAttachPhaseV3::Pending
            if observation.binding == [0; 32] && observation.witness.is_empty() =>
        {
            Ok(())
        }
        OriginalAttachPhaseV3::Ready | OriginalAttachPhaseV3::Transferred
            if observation.binding != [0; 32] =>
        {
            crate::openssh_monitor::OpenSshMonitorWitnessV2::decode_confined_v3(
                &observation.witness,
            )
            .map(|_| ())
            .map_err(|_| Error::InvalidEncoding)
        }
        _ => Err(Error::InvalidEncoding),
    }
}

fn section(bytes: &[u8], maximum: usize) -> Result<(&[u8], &[u8]), Error> {
    let length = u32::from_be_bytes(
        bytes
            .get(..4)
            .and_then(|b| b.try_into().ok())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openssh_gate::OpenSshGateBindingV1;

    fn original_ticket() -> Vec<u8> {
        let mut grant = [0; 416];
        grant[..8].copy_from_slice(b"AOSAPG01");
        grant[8..24].copy_from_slice(&[1; 16]);
        grant[24..40].copy_from_slice(&[2; 16]);
        aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2 {
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
            certificate: b"original-fixture-certificate".to_vec(),
        }
        .encode()
        .unwrap()
    }

    fn observation_request() -> OpenSshGateObserveRequestV1 {
        OpenSshGateObserveRequestV1 {
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
        }
    }

    #[test]
    fn narrowed_authority_deadline_cannot_extend_the_original_certificate() {
        let ticket = original_ticket();

        assert!(validate_expiry(20, &ticket).is_ok());
        assert!(validate_expiry(40, &ticket).is_ok());
        for expiry in [i64::MIN, -1, 0, 10, 41, i64::MAX] {
            assert!(validate_expiry(expiry, &ticket).is_err());
        }
    }

    #[test]
    fn original_request_preserves_both_deadlines_and_rejects_partial_or_foreign_shape() {
        let ticket = original_ticket();
        let observe = observation_request();
        let binding = [13; 32];
        let packet = encode_original_attach_request_v3(
            OriginalAttachActionV3::Consume,
            binding,
            30,
            1_234_567,
            &observe,
            &ticket,
        )
        .unwrap();
        let decoded = decode_original_attach_request_v3(&packet).unwrap();

        assert_eq!(decoded.0, OriginalAttachActionV3::Consume);
        assert_eq!(decoded.1, binding);
        assert_eq!(decoded.2, 30);
        assert_eq!(decoded.3, 1_234_567);
        assert_eq!(decoded.4, observe);
        assert_eq!(decoded.5, ticket);
        for length in 0..packet.len() {
            assert!(decode_original_attach_request_v3(&packet[..length]).is_err());
        }
        for range in [16..48, 48..56, 56..64] {
            let mut missing = packet.clone();
            missing[range].fill(0);
            assert!(decode_original_attach_request_v3(&missing).is_err());
        }
        for offset in [0, 8, 9, 64] {
            let mut substituted = packet.clone();
            substituted[offset] ^= 0xff;
            assert!(decode_original_attach_request_v3(&substituted).is_err());
        }
        let mut trailing = packet;
        trailing.push(0);
        assert!(decode_original_attach_request_v3(&trailing).is_err());
        assert!(
            encode_original_attach_request_v3(
                OriginalAttachActionV3::Consume,
                binding,
                30,
                0,
                &observe,
                &ticket,
            )
            .is_err()
        );
    }

    #[test]
    fn missing_foreign_partial_and_unknown_records_do_not_create_custody() {
        let observation = OriginalAttachObservationV3 {
            binding: [0; 32],
            phase: OriginalAttachPhaseV3::Pending,
            witness: Vec::new(),
        };
        let packet = encode_original_attach_response_v3(&observation, b"physical").unwrap();
        assert_eq!(
            decode_original_attach_response_v3(&packet).unwrap().0.phase,
            OriginalAttachPhaseV3::Pending
        );
        for length in 0..packet.len() {
            assert!(decode_original_attach_response_v3(&packet[..length]).is_err());
        }
        for offset in [0, 8, 9, 16, 48] {
            let mut foreign = packet.clone();
            foreign[offset] ^= 0xff;
            assert!(decode_original_attach_response_v3(&foreign).is_err());
        }
        assert!(validate_action(OriginalAttachActionV3::Consume, [0; 32]).is_err());
        assert!(validate_action(OriginalAttachActionV3::Poll, [1; 32]).is_err());
    }
}
