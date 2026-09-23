//! Canonical Host broker request and physical OpenSSH gate evidence bodies.
//!
//! ```text
//! request = InstallHostAttachGateRequestV1 { header, pending_grant: AOSAPG01[416] }
//! response = HostAttachGateEvidenceV1 { exact route, signed_gate_readback }
//! ```
//!
//! This layer validates wire shape and the request/response cross-link. The
//! Host independently verifies the dedicated grant signature, protected lease,
//! deployment trust, admitted execution, and guest physical measurement.

use aos_proto::aos::sandbox::local::v1::{
    HostAttachGateEvidenceV1, InstallHostAttachGateRequestV1,
};
use aos_sandbox_core::ProtocolId;
use aos_sandbox_core::public_attach_grant::PUBLIC_ATTACH_GRANT_BYTES;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, exact_nonzero,
    validate_request_header,
};

const MAXIMUM_REQUEST_BODY_BYTES: usize = 1024;
const MAXIMUM_RESPONSE_BODY_BYTES: usize = 8192;

/// Carries an exact pending-grant packet from an authenticated controller peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostAttachGateRequestV1 {
    header: ValidatedHeader,
    pending_grant: [u8; PUBLIC_ATTACH_GRANT_BYTES],
    operation_id: [u8; 16],
    execution_id: [u8; 16],
}

impl ValidatedHostAttachGateRequestV1 {
    /// Returns the session-bound broker request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact still-untrusted dedicated-key signed grant packet.
    #[must_use]
    pub const fn pending_grant(&self) -> &[u8; PUBLIC_ATTACH_GRANT_BYTES] {
        &self.pending_grant
    }

    /// Returns the signed packet's operation selector for response cross-linking.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the signed packet's execution selector for response cross-linking.
    #[must_use]
    pub const fn execution_id(&self) -> [u8; 16] {
        self.execution_id
    }
}

/// Decodes one canonical, bounded Host gate-install request.
///
/// # Errors
///
/// Rejects unknown fields, wrong grant length/magic, missing identities, or
/// a foreign or expired broker request header.
pub fn decode_host_attach_gate_request_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostAttachGateRequestV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = InstallHostAttachGateRequestV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )?;
    let pending_grant: [u8; PUBLIC_ATTACH_GRANT_BYTES] = request
        .pending_grant
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("pending_grant"))?;
    if &pending_grant[..8] != b"AOSAPG01" {
        return Err(ProtocolValidationError::InvalidField("pending_grant"));
    }
    let operation_id = exact_nonzero::<16>(&pending_grant[8..24], "operation_id")?;
    let execution_id = exact_nonzero::<16>(&pending_grant[24..40], "execution_id")?;
    Ok(ValidatedHostAttachGateRequestV1 {
        header,
        pending_grant,
        operation_id,
        execution_id,
    })
}

/// Validates a complete signed-session Host gate response against its request.
///
/// The response's presence attests that Host completed signed physical
/// readback; the controller still checks the protected pending operation,
/// principal, audit, and external CA trust before certificate issuance.
///
/// # Errors
///
/// Rejects missing, extra, unbounded, or cross-linked route/readback fields.
pub fn decode_host_attach_gate_evidence_v1(
    bytes: &[u8],
    request: &ValidatedHostAttachGateRequestV1,
) -> Result<HostAttachGateEvidenceV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let evidence = HostAttachGateEvidenceV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !evidence.__buffa_unknown_fields.is_empty() || evidence.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    exact_nonzero::<32>(&evidence.route_digest, "route_digest")?;
    let observation = exact_nonzero::<32>(
        &evidence.gate_observation_commitment,
        "gate_observation_commitment",
    )?;
    let signed_length = if evidence.signed_gate_readback.len() >= 76
        && evidence.signed_gate_readback.starts_with(b"AOSSGR01")
    {
        let json_length = u32::from_be_bytes(
            evidence.signed_gate_readback[8..12]
                .try_into()
                .map_err(|_| ProtocolValidationError::InvalidField("signed_gate_readback"))?,
        ) as usize;
        if json_length == 0 {
            0
        } else {
            12usize.saturating_add(json_length).saturating_add(64)
        }
    } else {
        0
    };
    let mut commitment = Sha256::new();
    commitment.update(b"aos.sandbox.openssh-gate-readback-commitment.v1\0");
    commitment.update(&evidence.signed_gate_readback);

    if exact_nonzero::<16>(&evidence.operation_id, "operation_id")? != request.operation_id()
        || exact_nonzero::<16>(&evidence.execution_id, "execution_id")? != request.execution_id()
        || exact_nonzero::<16>(&evidence.incarnation_id, "incarnation_id")?
            != request.pending_grant[56..72]
        || evidence.assignment_epoch
            != u64::from_be_bytes(
                request.pending_grant[88..96]
                    .try_into()
                    .map_err(|_| ProtocolValidationError::InvalidField("assignment_epoch"))?,
            )
        || exact_nonzero::<16>(&evidence.principal_id, "principal_id")?
            != request.pending_grant[184..200]
        || exact_nonzero::<16>(&evidence.audit_id, "audit_id")? != request.pending_grant[200..216]
        || evidence.host.is_empty()
        || evidence.host.len() > 255
        || evidence.port == 0
        || evidence.port > u32::from(u16::MAX)
        || evidence.user.is_empty()
        || evidence.user.len() > 32
        || evidence.host_public_key.is_empty()
        || evidence.host_public_key.len() > 128
        || evidence.trusted_user_ca_public_key.is_empty()
        || evidence.trusted_user_ca_public_key.len() > 128
        || evidence.expires_at <= 0
        || evidence.expires_at
            != i64::from_be_bytes(
                request.pending_grant[216..224]
                    .try_into()
                    .map_err(|_| ProtocolValidationError::InvalidField("expires_at"))?,
            )
        || evidence.route_generation == 0
        || evidence.signed_gate_readback.len() != signed_length
        || signed_length > 4172
        || observation != <[u8; 32]>::from(commitment.finalize())
    {
        return Err(ProtocolValidationError::InvalidField(
            "host_attach_gate_evidence",
        ));
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        Audience, HostAttachGateEvidenceV1, InstallHostAttachGateRequestV1, RequestHeader,
    };
    use aos_sandbox_core::public_attach_grant::{
        PublicAttachPendingGrantV1, sign_public_attach_pending_grant_v1,
    };
    use buffa::Message as _;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest as _, Sha256};

    use super::{decode_host_attach_gate_evidence_v1, decode_host_attach_gate_request_v1};
    use crate::{PeerCredentials, PeerPolicy};

    fn request() -> InstallHostAttachGateRequestV1 {
        let grant = sign_public_attach_pending_grant_v1(
            &PublicAttachPendingGrantV1 {
                operation_id: [1; 16],
                execution_id: [2; 16],
                sandbox_id: [10; 16],
                incarnation_id: [3; 16],
                node_id: [11; 16],
                assignment_epoch: 4,
                desired_generation: 1,
                namespace_generation: 1,
                assignment_digest: [12; 32],
                lease_generation: 1,
                lease_digest: [13; 32],
                principal_id: [5; 16],
                audit_id: [6; 16],
                expires_at: 7,
                request_digest: [14; 32],
                pending_digest: [15; 32],
                trust_digest: [16; 32],
                gate_config_digest: [17; 32],
            },
            &SigningKey::from_bytes(&[1; 32]),
        )
        .unwrap();

        InstallHostAttachGateRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 0,
                request_id: vec![9; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 20,
                maximum_response_bytes: 8192,
                ..Default::default()
            })
            .into(),
            pending_grant: grant.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn response_crosslinks_pending_grant_and_exact_readback_packet() {
        let request = decode_host_attach_gate_request_v1(
            &request().encode_to_vec(),
            PeerCredentials {
                uid: 100,
                gid: 101,
                pid: Some(102),
            },
            PeerPolicy {
                uid: 100,
                gid: Some(101),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            10,
        )
        .unwrap();
        let mut readback = b"AOSSGR01".to_vec();
        readback.extend_from_slice(&2u32.to_be_bytes());
        readback.extend_from_slice(b"{}");
        readback.extend_from_slice(&[0; 64]);
        let mut commitment = Sha256::new();
        commitment.update(b"aos.sandbox.openssh-gate-readback-commitment.v1\0");
        commitment.update(&readback);
        let evidence = HostAttachGateEvidenceV1 {
            operation_id: vec![1; 16],
            execution_id: vec![2; 16],
            incarnation_id: vec![3; 16],
            assignment_epoch: 4,
            principal_id: vec![5; 16],
            audit_id: vec![6; 16],
            host: "guest.example".into(),
            port: 2222,
            user: "aos_exec".into(),
            host_public_key: b"ssh-ed25519 AAAA".to_vec(),
            trusted_user_ca_public_key: b"ssh-ed25519 BBBB".to_vec(),
            expires_at: 7,
            route_generation: 1,
            route_digest: vec![8; 32],
            gate_observation_commitment: commitment.finalize().to_vec(),
            signed_gate_readback: readback,
            ..Default::default()
        };
        assert!(decode_host_attach_gate_evidence_v1(&evidence.encode_to_vec(), &request).is_ok());

        let mut different_operation = evidence.clone();
        different_operation.operation_id[0] ^= 1;
        assert!(
            decode_host_attach_gate_evidence_v1(&different_operation.encode_to_vec(), &request)
                .is_err()
        );

        let mut changed_readback = evidence;
        changed_readback.signed_gate_readback[12] ^= 1;
        assert!(
            decode_host_attach_gate_evidence_v1(&changed_readback.encode_to_vec(), &request)
                .is_err()
        );
    }
}
