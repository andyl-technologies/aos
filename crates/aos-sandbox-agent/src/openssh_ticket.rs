//! Binding-only requests and fresh signed physical ticket readback.
//!
//! ```text
//! request = ticket_length:u32 | AOSTKB02 | observation_length:u32 | JSON
//! readback = AOSTGR02 | ticket_sha256[32] | length:u32 | AOSSGR01 | signature[64]
//! ```
//!
//! The existing Guest signing key attests physical installation, not SSH
//! authentication. Callback output, process ancestry, and this measurement
//! remain insufficient for I/O without the distinct trusted monitor and held
//! original-ticket consume owners.
//!
//! The trusted interface must carry the root sshd monitor's exact
//! successfully authenticated certificate/holder, SSH session commitment, and
//! monitor-owned post-auth child/private-connection identity. It must compare
//! that custody with this original ticket, not accept a tenant reflection of
//! public claim bytes. No such authorizing constructor exists in this module.
//!
//! Final consume additionally requires continuously held current Controller
//! policy/revocation/trust/expiry, Host assignment/lease, and Guest process and
//! cancellation fences through one-use reservation and descriptor send. The
//! relay additionally requires shell-free dispatch and qualified continuous
//! memory/procfd/descriptor confinement. A fresh physical measurement alone
//! is only a point-in-time sample.

use aos_sandbox_core::public_attach_ticket::{
    PUBLIC_ATTACH_TICKET_MAXIMUM_BYTES_V2, PublicAttachTicketBindingV2,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::openssh_gate::{
    OpenSshGateObserveRequestV1, OpenSshGateReadbackErrorV1 as Error, OpenSshGateReadbackV1,
    sign_openssh_gate_readback_v1, verify_openssh_gate_readback_v1,
};

const DOMAIN: &[u8] = b"aos.sandbox.openssh-ticket-physical-readback.v2\0";
const MAGIC: &[u8; 8] = b"AOSTGR02";
/// Bounds either complete binding-only request or signed readback.
pub const MAXIMUM_TICKET_GATE_BYTES_V2: usize = 16 * 1024;
/// Names the immutable root-owned ticket claim for later trusted custody.
pub const OPENSSH_TICKET_CLAIM_PATH_V2: &str = "/etc/aos/sandbox-attach/original-ticket-v2";

/// Encodes one exact ticket and a fresh session-bound observation.
///
/// # Errors
/// Rejects malformed ticket data, observations, or oversized encodings.
pub fn encode_ticket_gate_request_v2(
    observe: &OpenSshGateObserveRequestV1,
    ticket: &[u8],
) -> Result<Vec<u8>, Error> {
    observe.validate()?;
    PublicAttachTicketBindingV2::decode(ticket).map_err(|_| Error::InvalidEncoding)?;
    let json = serde_json::to_vec(observe).map_err(|_| Error::InvalidEncoding)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &u32::try_from(ticket.len())
            .map_err(|_| Error::InvalidEncoding)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(ticket);
    bytes.extend_from_slice(
        &u32::try_from(json.len())
            .map_err(|_| Error::InvalidEncoding)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&json);
    if bytes.len() > MAXIMUM_TICKET_GATE_BYTES_V2 {
        return Err(Error::InvalidEncoding);
    }
    Ok(bytes)
}

/// Decodes a canonical bounded binding-only request without creating authority.
///
/// # Errors
/// Rejects unknown ticket versions, partial/trailing data, and noncanonical JSON.
pub fn decode_ticket_gate_request_v2(
    bytes: &[u8],
) -> Result<(OpenSshGateObserveRequestV1, &[u8]), Error> {
    if bytes.len() > MAXIMUM_TICKET_GATE_BYTES_V2 {
        return Err(Error::InvalidEncoding);
    }
    let (ticket, rest) = section(bytes, PUBLIC_ATTACH_TICKET_MAXIMUM_BYTES_V2)?;
    PublicAttachTicketBindingV2::decode(ticket).map_err(|_| Error::InvalidEncoding)?;
    let (json, rest) = section(rest, 4096)?;
    let observe: OpenSshGateObserveRequestV1 =
        serde_json::from_slice(json).map_err(|_| Error::InvalidEncoding)?;
    observe.validate()?;
    if !rest.is_empty() || serde_json::to_vec(&observe).map_err(|_| Error::InvalidEncoding)? != json
    {
        return Err(Error::InvalidEncoding);
    }
    Ok((observe, ticket))
}

/// Signs a fresh physical measurement of the immutable installed ticket.
///
/// # Errors
/// Rejects invalid readback or a missing ticket commitment. Callers must obtain
/// the commitment by reading the actual protected claim, not reflecting a request.
pub fn sign_ticket_gate_readback_v2(
    gate: &OpenSshGateReadbackV1,
    ticket_digest: [u8; 32],
    key: &SigningKey,
) -> Result<Vec<u8>, Error> {
    if ticket_digest == [0; 32] {
        return Err(Error::InvalidEncoding);
    }
    let base = sign_openssh_gate_readback_v1(gate, key)?;
    let mut packet = MAGIC.to_vec();
    packet.extend_from_slice(&ticket_digest);
    packet.extend_from_slice(
        &u32::try_from(base.len())
            .map_err(|_| Error::InvalidEncoding)?
            .to_be_bytes(),
    );
    packet.extend_from_slice(&base);
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&packet);
    packet.extend_from_slice(&key.sign(&message).to_bytes());
    Ok(packet)
}

/// Verifies a ticket measurement while preserving the original v1 readback.
///
/// # Errors
/// Rejects oversized/partial packets, substitution, or either invalid signature.
pub fn verify_ticket_gate_readback_v2<'a>(
    packet: &'a [u8],
    public_key: &[u8; 32],
) -> Result<(OpenSshGateReadbackV1, [u8; 32], &'a [u8]), Error> {
    if packet.len() > MAXIMUM_TICKET_GATE_BYTES_V2 || packet.get(..8) != Some(MAGIC.as_slice()) {
        return Err(Error::InvalidEncoding);
    }
    let digest: [u8; 32] = packet
        .get(8..40)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(Error::InvalidEncoding)?;
    if digest == [0; 32] {
        return Err(Error::InvalidEncoding);
    }
    let (base, signature) = section(packet.get(40..).ok_or(Error::InvalidEncoding)?, 8192)?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidEncoding)?;
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| Error::InvalidSignature)?;
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&packet[..packet.len() - 64]);
    key.verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| Error::InvalidSignature)?;
    let (gate, _) = verify_openssh_gate_readback_v1(base, public_key)?;
    Ok((gate, digest, base))
}

/// Computes the non-authorizing commitment to exact immutable ticket bytes.
#[must_use]
pub fn ticket_digest_v2(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Checks the retained holder and certificate against the protected gate profile.
///
/// # Errors
/// Rejects mismatched original identities, route, holder, validity, CA or profile.
/// This checks exact stored data, not possession or current attach authorization.
pub fn validate_ticket_profile_v2(
    claim: &crate::openssh_gate::OpenSshGateClaimV1,
    ticket: &PublicAttachTicketBindingV2,
    now: u64,
) -> Result<(), Error> {
    checked_ticket_certificate_v2(claim, ticket, now).map(|_| ())
}

// The callback and root-monitor witness need the same checked original profile;
// returning the parsed certificate avoids reparsing without combining authority.
pub(crate) fn checked_ticket_certificate_v2(
    claim: &crate::openssh_gate::OpenSshGateClaimV1,
    ticket: &PublicAttachTicketBindingV2,
    now: u64,
) -> Result<ssh_key::Certificate, Error> {
    let line = std::str::from_utf8(&ticket.certificate).map_err(|_| Error::InvalidEncoding)?;
    let (kind, base64) = line.split_once(' ').ok_or(Error::InvalidEncoding)?;
    let certificate = crate::openssh_attach_certificate::checked_openssh_attach_certificate_v1(
        claim, kind, base64, now,
    )
    .map_err(|_| Error::InvalidBinding)?;
    let binding = &claim.binding;
    if ticket.operation_id != binding.attach_operation_id
        || ticket.execution_id != binding.execution_id
        || ticket.incarnation_id != binding.incarnation_id
        || ticket.principal_id != binding.principal_id
        || ticket.audit_id != binding.audit_id
        || ticket.assignment_epoch != binding.assignment_epoch
        || ticket.base_route_digest != claim.route_digest
        || certificate.public_key().ed25519().map(|key| key.0) != Some(ticket.holder_public_key)
        || certificate.valid_after() != ticket.valid_after
        || certificate.valid_before() != ticket.expires_at
    {
        return Err(Error::InvalidBinding);
    }
    Ok(certificate)
}

/// Checks sshd's actual certificate against the exact original stored ticket.
///
/// # Errors
/// Rejects another certificate even when it has the same CA, holder and route
/// profile. This callback-side check is not trusted post-authentication custody.
pub fn validate_original_ticket_certificate_v2(
    claim: &crate::openssh_gate::OpenSshGateClaimV1,
    ticket_bytes: &[u8],
    certificate_type: &str,
    certificate_base64: &str,
    now: u64,
) -> Result<(), Error> {
    let ticket =
        PublicAttachTicketBindingV2::decode(ticket_bytes).map_err(|_| Error::InvalidEncoding)?;
    let actual = format!("{certificate_type} {certificate_base64}");
    if actual.as_bytes() != ticket.certificate {
        return Err(Error::InvalidBinding);
    }
    validate_ticket_profile_v2(claim, &ticket, now)
}

fn section(bytes: &[u8], maximum: usize) -> Result<(&[u8], &[u8]), Error> {
    let length = u32::from_be_bytes(
        bytes
            .get(..4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(Error::InvalidEncoding)?,
    ) as usize;
    let end = 4usize.checked_add(length).ok_or(Error::InvalidEncoding)?;
    if length == 0 || length > maximum {
        return Err(Error::InvalidEncoding);
    }
    Ok((
        bytes.get(4..end).ok_or(Error::InvalidEncoding)?,
        bytes.get(end..).ok_or(Error::InvalidEncoding)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openssh_gate::{OpenSshGateBindingV1, OpenSshGatePhysicalStateV1};

    #[test]
    fn signed_ticket_measurement_preserves_v1_and_rejects_partial_or_substituted_packets() {
        let gate = OpenSshGateReadbackV1 {
            challenge: [1; 32],
            route_digest: [2; 32],
            channel_binding: [3; 32],
            binding: OpenSshGateBindingV1 {
                attach_operation_id: [4; 16],
                execution_id: [5; 16],
                incarnation_id: [6; 16],
                assignment_epoch: 1,
                principal_id: [7; 16],
                audit_id: [8; 16],
                user: "aos_exec".to_owned(),
                port: 2222,
                host_public_key: "ssh-ed25519 AAAA".to_owned(),
                trusted_user_ca_public_key: "ssh-ed25519 BBBB".to_owned(),
                expires_at: 1300,
                gate_config_digest: [9; 32],
            },
            physical: OpenSshGatePhysicalStateV1 {
                sshd_pid: 10,
                sshd_start_ticks: 11,
                sshd_executable_digest: [12; 32],
                gate_executable_digest: [13; 32],
                host_private_key_digest: [14; 32],
            },
        };
        let key = SigningKey::from_bytes(&[15; 32]);
        let public = key.verifying_key().to_bytes();
        let digest = [16; 32];
        let packet = sign_ticket_gate_readback_v2(&gate, digest, &key).unwrap();
        let (observed, observed_digest, original_v1) =
            verify_ticket_gate_readback_v2(&packet, &public).unwrap();
        assert_eq!(observed, gate);
        assert_eq!(observed_digest, digest);
        assert_eq!(
            original_v1,
            sign_openssh_gate_readback_v1(&gate, &key).unwrap()
        );
        for length in 0..packet.len() {
            assert!(verify_ticket_gate_readback_v2(&packet[..length], &public).is_err());
        }
        for offset in [8, 40, 44, packet.len() - 1] {
            let mut changed = packet.clone();
            changed[offset] ^= 1;
            assert!(verify_ticket_gate_readback_v2(&changed, &public).is_err());
        }
        assert!(
            verify_ticket_gate_readback_v2(
                &packet,
                &SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes()
            )
            .is_err()
        );
        let mut fresh = gate.clone();
        fresh.challenge = [18; 32];
        let fresh_packet = sign_ticket_gate_readback_v2(&fresh, digest, &key).unwrap();
        assert_ne!(packet, fresh_packet);
        assert_eq!(
            verify_ticket_gate_readback_v2(&fresh_packet, &public)
                .unwrap()
                .0
                .challenge,
            fresh.challenge
        );
    }

    #[test]
    fn request_sections_reject_unbounded_lengths_before_allocation() {
        assert!(decode_ticket_gate_request_v2(&u32::MAX.to_be_bytes()).is_err());
        assert!(decode_ticket_gate_request_v2(&[0; 4]).is_err());
        assert!(decode_ticket_gate_request_v2(&vec![0; MAXIMUM_TICKET_GATE_BYTES_V2 + 1]).is_err());
    }
}
