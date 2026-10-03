//! Bounded original-ticket holder witnesses from the privileged SSH monitor.
//!
//! Parsing or verifying these public bytes does not identify their sender. The
//! Guest separately requires its live measured root monitor, private connection
//! and owned post-auth child pidfd. Callback output is never an input. This
//! prerequisite cannot reserve an attach or transfer execution descriptors.
//!
//! ```text
//! AOSAMR02 | uid:u32 | gid:u32 | session:string | certificate:string
//!          | original_userauth_message:string | holder_signature:string
//! AOSAMR03 uses the same bounded fields, but its measured producer waits for
//! irreversible post-auth confinement before publishing the record.
//! ```
//!
//! Strings have a big-endian u32 length. One separately transferred descriptor
//! must be the monitor's own post-auth child pidfd, never an I/O descriptor.

use aos_sandbox_core::public_attach_route::PUBLIC_ATTACH_CERTIFICATE_TYPE_V1;
use aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2;
use ed25519_dalek::{Signature, VerifyingKey};
use ssh_key::PublicKey;

use crate::openssh_gate::OpenSshGateClaimV1;

/// Bounds the root-monitor carrier before allocation or parsing.
pub const OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2: usize = 13_312;
/// Acknowledges only retained binding, never readiness or I/O authority.
pub const OPENSSH_MONITOR_BINDING_ACK_V2: &[u8; 8] = b"AOSAMB02";

/// Borrows an untrusted monitor-shaped holder witness without authenticating it.
pub struct OpenSshMonitorWitnessV2<'a> {
    /// Claimed account UID, authenticated separately by the live root/child join.
    pub uid: u32,
    /// Claimed primary group, checked against the pinned accepted child.
    pub gid: u32,
    /// Original SSH key-exchange session identifier.
    pub session: &'a [u8],
    /// Claimed binary certificate, required to equal the original stored ticket.
    pub certificate: &'a [u8],
    /// Exact SSH authentication message covered by the holder signature.
    pub signed_message: &'a [u8],
    /// Original SSH-encoded Ed25519 holder signature.
    pub signature: &'a [u8],
}

impl<'a> OpenSshMonitorWitnessV2<'a> {
    /// Decodes one bounded, complete v2 record with a non-root login account.
    ///
    /// # Errors
    /// Rejects another version, partial/trailing bytes, or oversized sections.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, OpenSshMonitorWitnessErrorV2> {
        Self::decode_profile(bytes, b"AOSAMR02")
    }

    /// Decodes the fixed confined producer's v3 envelope without trusting it.
    ///
    /// This shape check does not attest confinement. The Guest must retain the
    /// measured root producer and exact private post-auth child independently.
    ///
    /// # Errors
    /// Rejects legacy records, another version, partial/trailing data or bounds.
    pub fn decode_confined_v3(bytes: &'a [u8]) -> Result<Self, OpenSshMonitorWitnessErrorV2> {
        Self::decode_profile(bytes, b"AOSAMR03")
    }

    fn decode_profile(
        bytes: &'a [u8],
        magic: &[u8; 8],
    ) -> Result<Self, OpenSshMonitorWitnessErrorV2> {
        if bytes.len() > OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2
            || bytes.get(..8) != Some(magic.as_slice())
        {
            return Err(OpenSshMonitorWitnessErrorV2);
        }
        let mut rest = bytes.get(8..).ok_or(OpenSshMonitorWitnessErrorV2)?;
        let uid = integer(&mut rest)?;
        let gid = integer(&mut rest)?;
        let session = section(&mut rest, 64)?;
        let certificate = section(&mut rest, 4096)?;
        let signed_message = section(&mut rest, 8192)?;
        let signature = section(&mut rest, 128)?;
        if uid == 0 || session.len() < 32 || !rest.is_empty() {
            return Err(OpenSshMonitorWitnessErrorV2);
        }
        Ok(Self {
            uid,
            gid,
            session,
            certificate,
            signed_message,
            signature,
        })
    }

    /// Verifies exact retained certificate and key/session-bound holder proof.
    ///
    /// This independently checks the public witness. Current account acceptance
    /// and trusted post-auth provenance still require the retained root owner.
    ///
    /// # Errors
    /// Rejects substitution, wrong holder/session/login/host, noncanonical SSH
    /// data, invalid signatures, or an expired protected ticket/profile.
    pub fn validate_original_holder(
        &self,
        claim: &OpenSshGateClaimV1,
        ticket: &PublicAttachTicketBindingV2,
        now: u64,
    ) -> Result<(), OpenSshMonitorWitnessErrorV2> {
        let certificate = crate::openssh_ticket::checked_ticket_certificate_v2(claim, ticket, now)
            .map_err(|_| OpenSshMonitorWitnessErrorV2)?;
        if certificate
            .to_bytes()
            .map_err(|_| OpenSshMonitorWitnessErrorV2)?
            != self.certificate
        {
            return Err(OpenSshMonitorWitnessErrorV2);
        }

        let mut message = self.signed_message;
        if section(&mut message, 64)? != self.session
            || byte(&mut message)? != 50 // SSH_MSG_USERAUTH_REQUEST
            || section(&mut message, 32)? != claim.binding.user.as_bytes()
            || section(&mut message, 32)? != b"ssh-connection"
        {
            return Err(OpenSshMonitorWitnessErrorV2);
        }
        let method = section(&mut message, 64)?;
        let hostbound = match method {
            b"publickey" => false,
            b"publickey-hostbound-v00@openssh.com" => true,
            _ => return Err(OpenSshMonitorWitnessErrorV2),
        };
        if byte(&mut message)? != 1
            || section(&mut message, 64)? != PUBLIC_ATTACH_CERTIFICATE_TYPE_V1.as_bytes()
            || section(&mut message, 4096)? != self.certificate
        {
            return Err(OpenSshMonitorWitnessErrorV2);
        }
        if hostbound {
            let host = PublicKey::from_openssh(&claim.binding.host_public_key)
                .map_err(|_| OpenSshMonitorWitnessErrorV2)?;
            if section(&mut message, 128)?
                != host.to_bytes().map_err(|_| OpenSshMonitorWitnessErrorV2)?
            {
                return Err(OpenSshMonitorWitnessErrorV2);
            }
        }
        if !message.is_empty() {
            return Err(OpenSshMonitorWitnessErrorV2);
        }

        let mut encoded_signature = self.signature;
        if section(&mut encoded_signature, 32)? != b"ssh-ed25519" {
            return Err(OpenSshMonitorWitnessErrorV2);
        }
        let raw_signature: [u8; 64] = section(&mut encoded_signature, 64)?
            .try_into()
            .map_err(|_| OpenSshMonitorWitnessErrorV2)?;
        if !encoded_signature.is_empty() {
            return Err(OpenSshMonitorWitnessErrorV2);
        }
        let holder = VerifyingKey::from_bytes(&ticket.holder_public_key)
            .map_err(|_| OpenSshMonitorWitnessErrorV2)?;
        holder
            .verify_strict(self.signed_message, &Signature::from_bytes(&raw_signature))
            .map_err(|_| OpenSshMonitorWitnessErrorV2)
    }
}

/// Reports an opaque rejected witness without logging certificate or handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("OpenSSH original-holder witness rejected")]
pub struct OpenSshMonitorWitnessErrorV2;

fn integer(rest: &mut &[u8]) -> Result<u32, OpenSshMonitorWitnessErrorV2> {
    let bytes = rest.get(..4).ok_or(OpenSshMonitorWitnessErrorV2)?;
    let value = u32::from_be_bytes(bytes.try_into().map_err(|_| OpenSshMonitorWitnessErrorV2)?);
    *rest = rest.get(4..).ok_or(OpenSshMonitorWitnessErrorV2)?;
    Ok(value)
}

fn byte(rest: &mut &[u8]) -> Result<u8, OpenSshMonitorWitnessErrorV2> {
    let value = *rest.first().ok_or(OpenSshMonitorWitnessErrorV2)?;
    *rest = rest.get(1..).ok_or(OpenSshMonitorWitnessErrorV2)?;
    Ok(value)
}

fn section<'a>(
    rest: &mut &'a [u8],
    maximum: usize,
) -> Result<&'a [u8], OpenSshMonitorWitnessErrorV2> {
    let length = usize::try_from(integer(rest)?).map_err(|_| OpenSshMonitorWitnessErrorV2)?;
    if length == 0 || length > maximum {
        return Err(OpenSshMonitorWitnessErrorV2);
    }
    let bytes = rest.get(..length).ok_or(OpenSshMonitorWitnessErrorV2)?;
    *rest = rest.get(length..).ok_or(OpenSshMonitorWitnessErrorV2)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
