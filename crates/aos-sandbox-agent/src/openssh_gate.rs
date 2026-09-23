//! Signed, bounded physical readback for one OpenSSH attach gate.
//!
//! The guest signs only a measurement of installed files and a live daemon
//! that it owns. The Host compares every route field and the fresh challenge
//! against protected state before an attach certificate can be issued.
//!
//! ```text
//! AOSSGR01 || json_length:u32be || canonical JSON readback || signature[64]
//! signature = Ed25519("aos.sandbox.openssh-gate-readback.v1\0" || frame_without_signature)
//! ```

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSSGR01";
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.openssh-gate-readback.v1\0";
const MAXIMUM_JSON_BYTES: usize = 4096;
const SIGNATURE_BYTES: usize = 64;
const BRIDGE_MAGIC: &[u8; 8] = b"AOSGAB01";
const BRIDGE_REQUEST_BYTES: usize = 172;

/// Names the route that the guest's OpenSSH gate must enforce exactly.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenSshGateBindingV1 {
    /// Admitted attach operation.
    pub attach_operation_id: [u8; 16],
    /// Execution selected by the attach operation.
    pub execution_id: [u8; 16],
    /// Current guest incarnation.
    pub incarnation_id: [u8; 16],
    /// Current assignment epoch.
    pub assignment_epoch: u64,
    /// Principal named by the certificate and gate.
    pub principal_id: [u8; 16],
    /// Audit row named by the certificate and gate.
    pub audit_id: [u8; 16],
    /// Guest login account.
    pub user: String,
    /// Guest OpenSSH listener port.
    pub port: u16,
    /// Canonical Ed25519 server host public key.
    pub host_public_key: String,
    /// Canonical Ed25519 user CA public key actually trusted by sshd.
    pub trusted_user_ca_public_key: String,
    /// Expiry of the protected route and installed gate.
    pub expires_at: i64,
    /// Digest of exact effective sshd configuration bytes.
    pub gate_config_digest: [u8; 32],
}

impl OpenSshGateBindingV1 {
    /// Rejects empty identities and malformed bounded route fields.
    ///
    /// # Errors
    ///
    /// Returns [`OpenSshGateReadbackErrorV1::InvalidBinding`] for sentinel or
    /// unbounded values.
    pub fn validate(&self) -> Result<(), OpenSshGateReadbackErrorV1> {
        if self.attach_operation_id == [0; 16]
            || self.execution_id == [0; 16]
            || self.incarnation_id == [0; 16]
            || self.assignment_epoch == 0
            || self.principal_id == [0; 16]
            || self.audit_id == [0; 16]
            || self.user.is_empty()
            || self.user.len() > 32
            || self.port == 0
            || self.host_public_key.is_empty()
            || self.host_public_key.len() > 128
            || self.trusted_user_ca_public_key.is_empty()
            || self.trusted_user_ca_public_key.len() > 128
            || self.expires_at <= 0
            || self.gate_config_digest == [0; 32]
        {
            return Err(OpenSshGateReadbackErrorV1::InvalidBinding);
        }
        Ok(())
    }
}

/// Reports measurements collected from the actual installed gate and daemon.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenSshGatePhysicalStateV1 {
    /// PID of the live sshd process serving this gate.
    pub sshd_pid: u32,
    /// Linux process start time, preventing PID reuse from matching readback.
    pub sshd_start_ticks: u64,
    /// Digest of the root-owned sshd executable observed through procfs.
    pub sshd_executable_digest: [u8; 32],
    /// Digest of the root-owned forced-command executable.
    pub gate_executable_digest: [u8; 32],
    /// Digest of the exact root-owned private host key file.
    pub host_private_key_digest: [u8; 32],
}

/// Carries a fresh guest measurement of one protected route.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenSshGateReadbackV1 {
    /// Host-generated challenge for this one observation.
    pub challenge: [u8; 32],
    /// Exact protected Host route record commitment.
    pub route_digest: [u8; 32],
    /// Protected Host-to-agent channel binding.
    pub channel_binding: [u8; 32],
    /// Exact route fields measured in the guest.
    pub binding: OpenSshGateBindingV1,
    /// Concrete daemon and file measurements.
    pub physical: OpenSshGatePhysicalStateV1,
}

/// Requests installation and a fresh physical observation on one agent session.
///
/// The guest must derive process identity from its protected execution ledger;
/// this request supplies only the already-admitted route and challenge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenSshGateObserveRequestV1 {
    /// Exact authenticated agent handshake binding.
    pub session_binding: [u8; 32],
    /// Fresh Host-generated challenge.
    pub challenge: [u8; 32],
    /// Protected Host route record commitment.
    pub route_digest: [u8; 32],
    /// Exact installed route, including the admitted attach operation.
    pub binding: OpenSshGateBindingV1,
}

impl OpenSshGateObserveRequestV1 {
    /// Rejects sentinel identities before dispatching any guest installation.
    ///
    /// # Errors
    ///
    /// Returns an error when a route or challenge is missing or malformed.
    pub fn validate(&self) -> Result<(), OpenSshGateReadbackErrorV1> {
        self.binding.validate()?;
        if self.session_binding == [0; 32]
            || self.challenge == [0; 32]
            || self.route_digest == [0; 32]
        {
            return Err(OpenSshGateReadbackErrorV1::InvalidBinding);
        }
        Ok(())
    }
}

/// Root-installed attach claim consumed by the unprivileged forced command.
///
/// The guest process owner also reads this claim under root-only ledger custody
/// before passing its held PTY descriptor. The public file contains no private
/// host key, process specification, or credential material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenSshGateClaimV1 {
    /// Exact measured route enforced by sshd.
    pub binding: OpenSshGateBindingV1,
    /// Protected Host route record commitment.
    pub route_digest: [u8; 32],
    /// Guest process ledger runtime identity commitment.
    pub runtime_identity: [u8; 32],
    /// Exact running admitted process.
    pub process_pid: u32,
    /// Linux start ticks for the admitted process.
    pub process_start_ticks: u64,
    /// Exact guest-owned sshd listener process.
    pub sshd_pid: u32,
    /// Linux start ticks for the owned sshd listener.
    pub sshd_start_ticks: u64,
    /// True for PTY attach; false for three-descriptor stream attach.
    pub pty: bool,
}

impl OpenSshGateClaimV1 {
    /// Validates the non-sentinel route and process claim.
    ///
    /// # Errors
    ///
    /// Returns an error for missing route, runtime, or process identity.
    pub fn validate(&self) -> Result<(), OpenSshGateReadbackErrorV1> {
        self.binding.validate()?;
        if self.route_digest == [0; 32]
            || self.runtime_identity == [0; 32]
            || self.process_pid == 0
            || self.process_start_ticks == 0
            || self.sshd_pid == 0
            || self.sshd_start_ticks == 0
            || self.process_pid == self.sshd_pid
        {
            return Err(OpenSshGateReadbackErrorV1::InvalidBinding);
        }
        Ok(())
    }

    /// Encodes the exact fixed-size bridge request for this claim.
    ///
    /// # Errors
    ///
    /// Returns an error if the claim has sentinel fields.
    pub fn encode_bridge_request(
        &self,
    ) -> Result<[u8; BRIDGE_REQUEST_BYTES], OpenSshGateReadbackErrorV1> {
        self.validate()?;
        let mut bytes = [0u8; BRIDGE_REQUEST_BYTES];
        bytes[..8].copy_from_slice(BRIDGE_MAGIC);
        bytes[8..24].copy_from_slice(&self.binding.attach_operation_id);
        bytes[24..40].copy_from_slice(&self.binding.execution_id);
        bytes[40..56].copy_from_slice(&self.binding.incarnation_id);
        bytes[56..64].copy_from_slice(&self.binding.assignment_epoch.to_be_bytes());
        bytes[64..80].copy_from_slice(&self.binding.principal_id);
        bytes[80..96].copy_from_slice(&self.binding.audit_id);
        bytes[96..128].copy_from_slice(&self.route_digest);
        bytes[128..160].copy_from_slice(&self.runtime_identity);
        bytes[160..164].copy_from_slice(&self.process_pid.to_be_bytes());
        bytes[164..172].copy_from_slice(&self.process_start_ticks.to_be_bytes());
        Ok(bytes)
    }
}

/// Carries untrusted fixed-width fields from a gate-to-process bridge request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenSshGateBridgeRequestV1 {
    /// Attach operation selected by the certificate.
    pub operation: [u8; 16],
    /// Running guest execution.
    pub execution: [u8; 16],
    /// Current guest incarnation.
    pub incarnation: [u8; 16],
    /// Current assignment epoch.
    pub assignment_epoch: u64,
    /// Authenticated principal.
    pub principal: [u8; 16],
    /// Durable audit identity.
    pub audit: [u8; 16],
    /// Protected Host route record commitment.
    pub route_digest: [u8; 32],
    /// Protected guest process runtime commitment.
    pub runtime_identity: [u8; 32],
    /// Running process ID.
    pub process_pid: u32,
    /// Linux process start ticks.
    pub process_start_ticks: u64,
}

/// Decodes a fixed bridge request without trusting its claimed authority.
///
/// The guest process owner must compare the decoded request to its root-owned
/// claim and protected ledger before handing out the PTY descriptor.
///
/// # Errors
///
/// Returns an error for an invalid length, magic, or sentinel field.
pub fn decode_openssh_gate_bridge_request_v1(
    bytes: &[u8],
) -> Result<OpenSshGateBridgeRequestV1, OpenSshGateReadbackErrorV1> {
    if bytes.len() != BRIDGE_REQUEST_BYTES || &bytes[..8] != BRIDGE_MAGIC {
        return Err(OpenSshGateReadbackErrorV1::InvalidEncoding);
    }
    let operation = bytes[8..24]
        .try_into()
        .map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?;
    let execution = bytes[24..40]
        .try_into()
        .map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?;
    let incarnation = bytes[40..56]
        .try_into()
        .map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?;
    let epoch = u64::from_be_bytes(
        bytes[56..64]
            .try_into()
            .map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?,
    );
    let principal = bytes[64..80]
        .try_into()
        .map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?;
    let audit = bytes[80..96]
        .try_into()
        .map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?;
    let route = bytes[96..128]
        .try_into()
        .map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?;
    let runtime = bytes[128..160]
        .try_into()
        .map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?;
    let pid = u32::from_be_bytes(
        bytes[160..164]
            .try_into()
            .map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?,
    );
    let ticks = u64::from_be_bytes(
        bytes[164..172]
            .try_into()
            .map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?,
    );
    if operation == [0; 16]
        || execution == [0; 16]
        || incarnation == [0; 16]
        || epoch == 0
        || principal == [0; 16]
        || audit == [0; 16]
        || route == [0; 32]
        || runtime == [0; 32]
        || pid == 0
        || ticks == 0
    {
        return Err(OpenSshGateReadbackErrorV1::InvalidBinding);
    }
    Ok(OpenSshGateBridgeRequestV1 {
        operation,
        execution,
        incarnation,
        assignment_epoch: epoch,
        principal,
        audit,
        route_digest: route,
        runtime_identity: runtime,
        process_pid: pid,
        process_start_ticks: ticks,
    })
}

impl OpenSshGateReadbackV1 {
    /// Validates the bounded shape of one physical observation.
    ///
    /// # Errors
    ///
    /// Returns [`OpenSshGateReadbackErrorV1::InvalidBinding`] for missing
    /// challenges, route commitments, or physical process evidence.
    pub fn validate(&self) -> Result<(), OpenSshGateReadbackErrorV1> {
        self.binding.validate()?;
        if self.challenge == [0; 32]
            || self.route_digest == [0; 32]
            || self.channel_binding == [0; 32]
            || self.physical.sshd_pid == 0
            || self.physical.sshd_start_ticks == 0
            || self.physical.sshd_executable_digest == [0; 32]
            || self.physical.gate_executable_digest == [0; 32]
            || self.physical.host_private_key_digest == [0; 32]
        {
            return Err(OpenSshGateReadbackErrorV1::InvalidBinding);
        }
        Ok(())
    }
}

/// Encodes and signs a guest-owned, physically measured gate observation.
///
/// The caller must hold the protected guest-agent signing key and must only
/// pass values derived from fresh physical readback, not a Host route copy.
///
/// # Errors
///
/// Returns an error for invalid or oversized readback data.
pub fn sign_openssh_gate_readback_v1(
    readback: &OpenSshGateReadbackV1,
    key: &SigningKey,
) -> Result<Vec<u8>, OpenSshGateReadbackErrorV1> {
    readback.validate()?;
    let payload =
        serde_json::to_vec(readback).map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?;
    if payload.len() > MAXIMUM_JSON_BYTES {
        return Err(OpenSshGateReadbackErrorV1::InvalidEncoding);
    }
    let length =
        u32::try_from(payload.len()).map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?;
    let mut packet = Vec::with_capacity(8 + 4 + payload.len() + SIGNATURE_BYTES);
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&payload);

    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + packet.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&packet);
    packet.extend_from_slice(&key.sign(&message).to_bytes());
    Ok(packet)
}

/// Verifies a canonical guest readback packet against one protected peer key.
///
/// # Errors
///
/// Returns an error for an oversized, noncanonical, malformed, or incorrectly
/// signed packet.
pub fn verify_openssh_gate_readback_v1(
    packet: &[u8],
    public_key: &[u8; 32],
) -> Result<(OpenSshGateReadbackV1, [u8; 32]), OpenSshGateReadbackErrorV1> {
    if packet.len() < 8 + 4 + SIGNATURE_BYTES || &packet[..8] != MAGIC {
        return Err(OpenSshGateReadbackErrorV1::InvalidEncoding);
    }
    let length = u32::from_be_bytes(
        packet[8..12]
            .try_into()
            .map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?,
    ) as usize;
    if length == 0
        || length > MAXIMUM_JSON_BYTES
        || packet.len() != 8 + 4 + length + SIGNATURE_BYTES
    {
        return Err(OpenSshGateReadbackErrorV1::InvalidEncoding);
    }
    let payload = &packet[12..12 + length];
    let readback: OpenSshGateReadbackV1 =
        serde_json::from_slice(payload).map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?;
    readback.validate()?;
    if serde_json::to_vec(&readback).map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?
        != payload
    {
        return Err(OpenSshGateReadbackErrorV1::InvalidEncoding);
    }

    let signed_length = 12 + length;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + signed_length);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&packet[..signed_length]);
    let signature: [u8; SIGNATURE_BYTES] = packet[signed_length..]
        .try_into()
        .map_err(|_| OpenSshGateReadbackErrorV1::InvalidEncoding)?;
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| OpenSshGateReadbackErrorV1::InvalidSignature)?;
    key.verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| OpenSshGateReadbackErrorV1::InvalidSignature)?;

    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.openssh-gate-readback-commitment.v1\0");
    digest.update(packet);
    Ok((readback, digest.finalize().into()))
}

/// Reports invalid signed OpenSSH gate evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OpenSshGateReadbackErrorV1 {
    /// Route or physical evidence contains a sentinel or unbounded value.
    #[error("OpenSSH gate readback binding is invalid")]
    InvalidBinding,
    /// Packet is oversized, malformed, or noncanonical.
    #[error("OpenSSH gate readback packet is invalid")]
    InvalidEncoding,
    /// Detached signature does not match the protected guest-agent peer.
    #[error("OpenSSH gate readback signature is invalid")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::{
        OpenSshGateBindingV1, OpenSshGateClaimV1, OpenSshGatePhysicalStateV1,
        OpenSshGateReadbackV1, decode_openssh_gate_bridge_request_v1,
        sign_openssh_gate_readback_v1, verify_openssh_gate_readback_v1,
    };

    fn binding() -> OpenSshGateBindingV1 {
        OpenSshGateBindingV1 {
            attach_operation_id: [1; 16],
            execution_id: [2; 16],
            incarnation_id: [3; 16],
            assignment_epoch: 4,
            principal_id: [5; 16],
            audit_id: [6; 16],
            user: "aos_exec".to_owned(),
            port: 2222,
            host_public_key: "ssh-ed25519 AAAA".to_owned(),
            trusted_user_ca_public_key: "ssh-ed25519 BBBB".to_owned(),
            expires_at: 2_000_000_000,
            gate_config_digest: [7; 32],
        }
    }

    #[test]
    fn signed_readback_rejects_mutation_and_wrong_peer() {
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let readback = OpenSshGateReadbackV1 {
            challenge: [8; 32],
            route_digest: [9; 32],
            channel_binding: [10; 32],
            binding: binding(),
            physical: OpenSshGatePhysicalStateV1 {
                sshd_pid: 123,
                sshd_start_ticks: 456,
                sshd_executable_digest: [12; 32],
                gate_executable_digest: [13; 32],
                host_private_key_digest: [14; 32],
            },
        };
        let packet = sign_openssh_gate_readback_v1(&readback, &signing_key).unwrap();
        let (verified, commitment) =
            verify_openssh_gate_readback_v1(&packet, &signing_key.verifying_key().to_bytes())
                .unwrap();
        assert_eq!(verified, readback);
        assert_ne!(commitment, [0; 32]);

        let mut altered = packet.clone();
        altered[32] ^= 1;
        assert!(
            verify_openssh_gate_readback_v1(&altered, &signing_key.verifying_key().to_bytes(),)
                .is_err()
        );
        let other_key = SigningKey::from_bytes(&[15; 32]);
        assert!(
            verify_openssh_gate_readback_v1(&packet, &other_key.verifying_key().to_bytes(),)
                .is_err()
        );
    }

    #[test]
    fn bridge_request_binds_every_identity_and_process_field() {
        let claim = OpenSshGateClaimV1 {
            binding: binding(),
            route_digest: [16; 32],
            runtime_identity: [17; 32],
            process_pid: 123,
            process_start_ticks: 456,
            sshd_pid: 789,
            sshd_start_ticks: 1000,
            pty: true,
        };
        let request = claim.encode_bridge_request().unwrap();
        let decoded = decode_openssh_gate_bridge_request_v1(&request).unwrap();
        assert_eq!(decoded.operation, claim.binding.attach_operation_id);
        assert_eq!(decoded.execution, claim.binding.execution_id);
        assert_eq!(decoded.incarnation, claim.binding.incarnation_id);
        assert_eq!(decoded.assignment_epoch, claim.binding.assignment_epoch);
        assert_eq!(decoded.principal, claim.binding.principal_id);
        assert_eq!(decoded.audit, claim.binding.audit_id);
        assert_eq!(decoded.route_digest, claim.route_digest);
        assert_eq!(decoded.runtime_identity, claim.runtime_identity);
        assert_eq!(decoded.process_pid, claim.process_pid);
        assert_eq!(decoded.process_start_ticks, claim.process_start_ticks);

        let mut trailing = request.to_vec();
        trailing.push(0);
        assert!(decode_openssh_gate_bridge_request_v1(&trailing).is_err());
    }
}
