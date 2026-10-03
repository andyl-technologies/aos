//! Canonical Host broker request and physical OpenSSH gate evidence bodies.
//!
//! ```text
//! request = InstallHostAttachGateRequestV1 { header, pending_grant: AOSAPG01[416],
//!                                          original_ticket_binding_v2?: AOSTKB02,
//!                                          original_ticket_consume_v3?: custody[32] + challenge[32] }
//! response = HostAttachGateEvidenceV1 { exact route, signed_gate_readback,
//!                                      original_ticket_digest_v2?, signed_ticket_readback_v2?,
//!                                      original_attach_observation_v3?: AOSACR03 }
//! ```
//!
//! This layer validates wire shape and the request/response cross-link. The
//! Host independently verifies the dedicated grant signature, protected lease,
//! deployment trust, admitted execution, and guest physical measurement.
//! V2 only installs immutable custody data through the existing ATTACH plan.
//! It does not attest SSH authentication, authorize consumption, or renew a grant.
//! V3 commits an exact consume under already-held owner authority; its correlation
//! and observed custody bytes never create authority or substitute for currentness.

use aos_proto::aos::sandbox::local::v1::{
    HostAttachGateEvidenceV1, HostAttachGateReadinessV1, InstallHostAttachGateRequestV1,
    QueryHostAttachGateReadinessRequestV1, QueryHostAttachGateRouteRequestV1,
};
use aos_sandbox_core::ProtocolId;
use aos_sandbox_core::public_attach_grant::PUBLIC_ATTACH_GRANT_BYTES;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, exact_nonzero,
    validate_request_header,
};

/// Bounds the complete encoded Host attach-gate request body.
pub const HOST_ATTACH_GATE_MAXIMUM_REQUEST_BODY_BYTES: usize = 16 * 1024;
const MAXIMUM_RESPONSE_BODY_BYTES: usize = 64 * 1024;

/// Carries an exact pending-grant packet from an authenticated controller peer.
#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedHostAttachGateRequestV1 {
    header: ValidatedHeader,
    pending_grant: [u8; PUBLIC_ATTACH_GRANT_BYTES],
    operation_id: [u8; 16],
    execution_id: [u8; 16],
    original_ticket_binding_v2: Vec<u8>,
    original_ticket_consume_v3: Option<([u8; 32], [u8; 32])>,
    original_session_control_v5: Vec<u8>,
}

impl std::fmt::Debug for ValidatedHostAttachGateRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValidatedHostAttachGateRequestV1(<redacted>)")
    }
}

/// Carries a read-only advisory readiness query from the authenticated peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHostAttachReadinessRequestV1 {
    header: ValidatedHeader,
}

impl ValidatedHostAttachReadinessRequestV1 {
    /// Returns the session-bound query header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }
}

/// Carries exact accepted operation and execution selectors for fresh readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHostAttachRouteQueryV1 {
    header: ValidatedHeader,
    operation_id: [u8; 16],
    execution_id: [u8; 16],
}

impl ValidatedHostAttachRouteQueryV1 {
    /// Returns the session-bound query header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the accepted operation selector.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the admitted execution selector.
    #[must_use]
    pub const fn execution_id(&self) -> [u8; 16] {
        self.execution_id
    }
}

/// Decodes one canonical, bounded advisory Host readiness query.
///
/// # Errors
///
/// Rejects malformed or noncanonical protobuf and an invalid broker header.
pub fn decode_host_attach_readiness_request_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostAttachReadinessRequestV1, ProtocolValidationError> {
    if bytes.len() > HOST_ATTACH_GATE_MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = QueryHostAttachGateReadinessRequestV1::decode_from_slice(bytes)
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
    Ok(ValidatedHostAttachReadinessRequestV1 { header })
}

/// Decodes one canonical accepted-route query with exact nonzero selectors.
///
/// # Errors
///
/// Rejects malformed or noncanonical protobuf, invalid selectors, or header.
pub fn decode_host_attach_route_query_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostAttachRouteQueryV1, ProtocolValidationError> {
    if bytes.len() > HOST_ATTACH_GATE_MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = QueryHostAttachGateRouteRequestV1::decode_from_slice(bytes)
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
    Ok(ValidatedHostAttachRouteQueryV1 {
        header,
        operation_id: exact_nonzero::<16>(&request.operation_id, "operation_id")?,
        execution_id: exact_nonzero::<16>(&request.execution_id, "execution_id")?,
    })
}

/// Decodes complete advisory readiness evidence from a signed Host outcome.
///
/// # Errors
///
/// Rejects malformed, noncanonical, missing, or sentinel evidence fields.
pub fn decode_host_attach_readiness_v1(
    bytes: &[u8],
) -> Result<HostAttachGateReadinessV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let response = HostAttachGateReadinessV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    exact_nonzero::<32>(&response.session_binding, "session_binding")?;
    exact_nonzero::<16>(&response.incarnation_id, "incarnation_id")?;
    exact_nonzero::<32>(&response.assignment_digest, "assignment_digest")?;
    exact_nonzero::<32>(&response.lease_digest, "lease_digest")?;
    exact_nonzero::<32>(&response.trust_digest, "trust_digest")?;
    if response.assignment_epoch == 0 || response.lease_generation == 0 {
        return Err(ProtocolValidationError::InvalidField(
            "host_attach_gate_readiness",
        ));
    }
    Ok(response)
}

impl ValidatedHostAttachGateRequestV1 {
    /// Returns exact original-session control correlation and canonical request data.
    /// No selected process or scalar correlation creates permission.
    #[must_use]
    pub fn original_session_control_v5(&self) -> Option<([u8; 32], [u8; 32], &[u8])> {
        let bytes = &self.original_session_control_v5;
        let binding = bytes.get(..32)?.try_into().ok()?;
        let challenge = bytes.get(32..64)?.try_into().ok()?;
        Some((binding, challenge, bytes.get(64..)?))
    }

    /// Returns exact consume correlation, never an authorizing constructor.
    #[must_use]
    pub const fn original_ticket_consume_v3(&self) -> Option<([u8; 32], [u8; 32])> {
        self.original_ticket_consume_v3
    }

    /// Returns the exact non-authorizing v2 data, or absence for v1 install.
    #[must_use]
    pub fn original_ticket_binding_v2(&self) -> Option<&[u8]> {
        (!self.original_ticket_binding_v2.is_empty())
            .then_some(self.original_ticket_binding_v2.as_slice())
    }

    /// Compiles the exact install or binding-only argument commitment.
    ///
    /// # Errors
    /// Rejects malformed receipt or ticket data without authenticating it.
    pub fn semantics(
        &self,
        assignment: aos_sandbox_core::BrokerAssignment,
    ) -> Result<
        crate::semantics::host_attach_gate::CanonicalHostAttachGateSemanticsV1,
        crate::semantics::host_attach_gate::HostAttachGateSemanticErrorV1,
    > {
        if let Some((binding, challenge, request)) = self.original_session_control_v5() {
            return crate::semantics::host_attach_gate::canonical_host_attach_control_semantics_v5(
                assignment,
                self.pending_grant(),
                self.original_ticket_binding_v2().ok_or(
                    crate::semantics::host_attach_gate::HostAttachGateSemanticErrorV1::InvalidGrant,
                )?,
                aos_sandbox_core::ObjectDigest::from_bytes(binding),
                challenge,
                request,
            );
        }
        if let Some((binding, challenge)) = self.original_ticket_consume_v3() {
            return crate::semantics::host_attach_gate::canonical_host_attach_consume_semantics_v3(
                assignment,
                self.pending_grant(),
                self.original_ticket_binding_v2().ok_or(
                    crate::semantics::host_attach_gate::HostAttachGateSemanticErrorV1::InvalidGrant,
                )?,
                aos_sandbox_core::ObjectDigest::from_bytes(binding),
                challenge,
            );
        }
        match self.original_ticket_binding_v2() {
            Some(ticket) => {
                crate::semantics::host_attach_gate::canonical_host_attach_ticket_semantics_v2(
                    assignment,
                    self.pending_grant(),
                    ticket,
                )
            }
            None => crate::semantics::host_attach_gate::canonical_host_attach_gate_semantics_v1(
                assignment,
                self.pending_grant(),
            ),
        }
    }
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
    if bytes.len() > HOST_ATTACH_GATE_MAXIMUM_REQUEST_BODY_BYTES {
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
    if !request.original_ticket_binding_v2.is_empty() {
        let ticket = aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2::decode(
            &request.original_ticket_binding_v2,
        )
        .map_err(|_| ProtocolValidationError::InvalidField("original_ticket_binding_v2"))?;
        if ticket.pending_grant != pending_grant {
            return Err(ProtocolValidationError::InvalidField(
                "original_ticket_binding_v2",
            ));
        }
    }
    let original_ticket_consume_v3 = if request.original_ticket_consume_v3.is_empty() {
        None
    } else {
        if request.original_ticket_binding_v2.is_empty()
            || request.original_ticket_consume_v3.len() != 64
        {
            return Err(ProtocolValidationError::InvalidField(
                "original_ticket_consume_v3",
            ));
        }
        Some((
            exact_nonzero::<32>(&request.original_ticket_consume_v3[..32], "monitor_binding")?,
            exact_nonzero::<32>(
                &request.original_ticket_consume_v3[32..],
                "observation_challenge",
            )?,
        ))
    };
    if !request.original_session_control_v5.is_empty() {
        let bytes = &request.original_session_control_v5;
        if request.original_ticket_binding_v2.is_empty()
            || original_ticket_consume_v3.is_some()
            || bytes.len()
                > 64 + aos_sandbox_agent::openssh_control::OPENSSH_CONTROL_MAXIMUM_REQUEST_BYTES_V5
        {
            return Err(ProtocolValidationError::InvalidField(
                "original_session_control_v5",
            ));
        }
        exact_nonzero::<32>(
            bytes
                .get(..32)
                .ok_or(ProtocolValidationError::InvalidField(
                    "original_session_control_v5",
                ))?,
            "monitor_binding",
        )?;
        exact_nonzero::<32>(
            bytes
                .get(32..64)
                .ok_or(ProtocolValidationError::InvalidField(
                    "original_session_control_v5",
                ))?,
            "observation_challenge",
        )?;
        aos_sandbox_agent::openssh_control::OpenSshControlRequestV5::decode(
            bytes
                .get(64..)
                .ok_or(ProtocolValidationError::InvalidField(
                    "original_session_control_v5",
                ))?,
        )
        .map_err(|_| ProtocolValidationError::InvalidField("original_session_control_v5"))?;
    }
    Ok(ValidatedHostAttachGateRequestV1 {
        header,
        pending_grant,
        operation_id,
        execution_id,
        original_ticket_binding_v2: request.original_ticket_binding_v2,
        original_ticket_consume_v3,
        original_session_control_v5: request.original_session_control_v5,
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
    let evidence = decode_host_attach_gate_evidence_shape_v1(bytes)?;
    if let Some((binding, challenge, control)) = request.original_session_control_v5() {
        let (observation, physical) =
            aos_sandbox_agent::openssh_control_channel::decode_original_control_response_shape_v5(
                &evidence.original_session_observation_v5,
            )
            .map_err(|_| {
                ProtocolValidationError::InvalidField("original_session_observation_v5")
            })?;
        if observation.phase
            != aos_sandbox_agent::openssh_control_channel::OriginalControlPhaseV5::Applied
            || observation.binding != binding
            || observation.request != control
            || physical != evidence.signed_ticket_readback_v2
        {
            return Err(ProtocolValidationError::InvalidField(
                "original_session_observation_v5",
            ));
        }
        require_gate_challenge(&evidence, challenge)?;
    } else if !evidence.original_session_observation_v5.is_empty() {
        return Err(ProtocolValidationError::InvalidField(
            "original_session_observation_v5",
        ));
    }
    if request.original_ticket_consume_v3().is_none()
        && !evidence.original_attach_observation_v3.is_empty()
    {
        return Err(ProtocolValidationError::InvalidField(
            "original_attach_observation_v3",
        ));
    }
    if let Some((binding, challenge)) = request.original_ticket_consume_v3() {
        let (observation, physical) =
            aos_sandbox_agent::openssh_consume::decode_original_attach_response_v3(
                &evidence.original_attach_observation_v3,
            )
            .map_err(|_| ProtocolValidationError::InvalidField("original_attach_observation_v3"))?;
        if observation.binding != binding
            || observation.phase
                != aos_sandbox_agent::openssh_consume::OriginalAttachPhaseV3::Transferred
            || physical != evidence.signed_ticket_readback_v2
        {
            return Err(ProtocolValidationError::InvalidField(
                "original_attach_observation_v3",
            ));
        }
        require_gate_challenge(&evidence, challenge)?;
    }
    match request.original_ticket_binding_v2() {
        Some(ticket)
            if evidence.original_ticket_digest_v2.as_slice()
                == Sha256::digest(ticket).as_slice()
                && !evidence.signed_ticket_readback_v2.is_empty() => {}
        None if evidence.original_ticket_digest_v2.is_empty()
            && evidence.signed_ticket_readback_v2.is_empty() => {}
        _ => {
            return Err(ProtocolValidationError::InvalidField(
                "original_ticket_digest_v2",
            ));
        }
    }
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
        || evidence.expires_at
            != i64::from_be_bytes(
                request.pending_grant[216..224]
                    .try_into()
                    .map_err(|_| ProtocolValidationError::InvalidField("expires_at"))?,
            )
    {
        return Err(ProtocolValidationError::InvalidField(
            "host_attach_gate_evidence",
        ));
    }
    Ok(evidence)
}

fn require_gate_challenge(
    evidence: &HostAttachGateEvidenceV1,
    challenge: [u8; 32],
) -> Result<(), ProtocolValidationError> {
    // Fresh physical readback contains this exact correlation challenge;
    // signatures are independently checked by the authenticated owners.
    let packet = &evidence.signed_gate_readback;
    let length = u32::from_be_bytes(
        packet
            .get(8..12)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(ProtocolValidationError::InvalidField(
                "signed_gate_readback",
            ))?,
    ) as usize;
    if length > 8192 {
        return Err(ProtocolValidationError::InvalidField(
            "signed_gate_readback",
        ));
    }
    let readback: aos_sandbox_agent::openssh_gate::OpenSshGateReadbackV1 =
        serde_json::from_slice(packet.get(12..12 + length).ok_or(
            ProtocolValidationError::InvalidField("signed_gate_readback"),
        )?)
        .map_err(|_| ProtocolValidationError::InvalidField("signed_gate_readback"))?;
    if readback.challenge != challenge {
        return Err(ProtocolValidationError::InvalidField(
            "observation_challenge",
        ));
    }
    Ok(())
}

/// Validates a fresh Host route readback against an accepted operation query.
///
/// The caller must accept this body only inside a verified Host broker outcome
/// and independently check current controller operation/certificate state.
///
/// # Errors
///
/// Rejects malformed, unbounded, or mismatched evidence.
pub fn decode_host_attach_route_evidence_v1(
    bytes: &[u8],
    request: &ValidatedHostAttachRouteQueryV1,
) -> Result<HostAttachGateEvidenceV1, ProtocolValidationError> {
    let evidence = decode_host_attach_gate_evidence_shape_v1(bytes)?;
    if !evidence.original_session_observation_v5.is_empty() {
        let (observation, _) =
            aos_sandbox_agent::openssh_control_channel::decode_original_control_response_shape_v5(
                &evidence.original_session_observation_v5,
            )
            .map_err(|_| {
                ProtocolValidationError::InvalidField("original_session_observation_v5")
            })?;
        if observation.phase
            == aos_sandbox_agent::openssh_control_channel::OriginalControlPhaseV5::Applied
        {
            return Err(ProtocolValidationError::InvalidField(
                "original_session_observation_v5",
            ));
        }
    }
    if !evidence.original_attach_observation_v3.is_empty() {
        let (observation, _) =
            aos_sandbox_agent::openssh_consume::decode_original_attach_response_v3(
                &evidence.original_attach_observation_v3,
            )
            .map_err(|_| ProtocolValidationError::InvalidField("original_attach_observation_v3"))?;
        if observation.phase
            == aos_sandbox_agent::openssh_consume::OriginalAttachPhaseV3::Transferred
        {
            return Err(ProtocolValidationError::InvalidField(
                "original_attach_observation_v3",
            ));
        }
    }
    if exact_nonzero::<16>(&evidence.operation_id, "operation_id")? != request.operation_id()
        || exact_nonzero::<16>(&evidence.execution_id, "execution_id")? != request.execution_id()
    {
        return Err(ProtocolValidationError::InvalidField(
            "host_attach_gate_route",
        ));
    }
    Ok(evidence)
}

fn decode_host_attach_gate_evidence_shape_v1(
    bytes: &[u8],
) -> Result<HostAttachGateEvidenceV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let evidence = HostAttachGateEvidenceV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !evidence.original_session_observation_v5.is_empty() {
        let (_, physical) =
            aos_sandbox_agent::openssh_control_channel::decode_original_control_response_shape_v5(
                &evidence.original_session_observation_v5,
            )
            .map_err(|_| {
                ProtocolValidationError::InvalidField("original_session_observation_v5")
            })?;
        if physical != evidence.signed_ticket_readback_v2 {
            return Err(ProtocolValidationError::InvalidField(
                "original_session_observation_v5",
            ));
        }
    }
    if !evidence.original_attach_observation_v3.is_empty() {
        let (_, physical) = aos_sandbox_agent::openssh_consume::decode_original_attach_response_v3(
            &evidence.original_attach_observation_v3,
        )
        .map_err(|_| ProtocolValidationError::InvalidField("original_attach_observation_v3"))?;
        if physical != evidence.signed_ticket_readback_v2 {
            return Err(ProtocolValidationError::InvalidField(
                "original_attach_observation_v3",
            ));
        }
    }
    if !evidence.original_ticket_digest_v2.is_empty()
        || !evidence.signed_ticket_readback_v2.is_empty()
    {
        exact_nonzero::<32>(
            &evidence.original_ticket_digest_v2,
            "original_ticket_digest_v2",
        )?;
        let packet = &evidence.signed_ticket_readback_v2;
        if packet.len() < 108
            || packet.len() > 8192
            || packet.get(..8) != Some(b"AOSTGR02".as_slice())
            || packet.get(8..40) != Some(evidence.original_ticket_digest_v2.as_slice())
        {
            return Err(ProtocolValidationError::InvalidField(
                "signed_ticket_readback_v2",
            ));
        }
        let length = u32::from_be_bytes(
            packet[40..44]
                .try_into()
                .map_err(|_| ProtocolValidationError::InvalidField("signed_ticket_readback_v2"))?,
        ) as usize;
        if length > 8192 {
            return Err(ProtocolValidationError::InvalidField(
                "signed_ticket_readback_v2",
            ));
        }
        if packet.len() != 44 + length + 64
            || packet.get(44..44 + length) != Some(evidence.signed_gate_readback.as_slice())
        {
            return Err(ProtocolValidationError::InvalidField(
                "signed_ticket_readback_v2",
            ));
        }
    }
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

    exact_nonzero::<16>(&evidence.operation_id, "operation_id")?;
    exact_nonzero::<16>(&evidence.execution_id, "execution_id")?;
    exact_nonzero::<16>(&evidence.incarnation_id, "incarnation_id")?;
    exact_nonzero::<16>(&evidence.principal_id, "principal_id")?;
    exact_nonzero::<16>(&evidence.audit_id, "audit_id")?;

    if evidence.assignment_epoch == 0
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
        Audience, HostAttachGateEvidenceV1, HostAttachGateReadinessV1,
        InstallHostAttachGateRequestV1, QueryHostAttachGateReadinessRequestV1,
        QueryHostAttachGateRouteRequestV1, RequestHeader,
    };
    use aos_sandbox_core::public_attach_grant::{
        PublicAttachPendingGrantV1, sign_public_attach_pending_grant_v1,
    };
    use buffa::Message as _;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest as _, Sha256};

    use super::{
        decode_host_attach_gate_evidence_v1, decode_host_attach_gate_request_v1,
        decode_host_attach_readiness_request_v1, decode_host_attach_readiness_v1,
        decode_host_attach_route_query_v1,
    };
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

    fn original_ticket(pending_grant: [u8; 416]) -> Vec<u8> {
        aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2 {
            operation_id: [1; 16],
            execution_id: [2; 16],
            incarnation_id: [3; 16],
            principal_id: [5; 16],
            audit_id: [6; 16],
            assignment_epoch: 4,
            valid_after: 1,
            expires_at: 7,
            holder_public_key: [18; 32],
            request_digest: [14; 32],
            decision_digest: [19; 32],
            pending_grant,
            base_route_digest: [8; 32],
            certificate: b"original-certificate".to_vec(),
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn consume_requires_exact_original_ticket_and_canonical_nonzero_correlation() {
        let decode = |request: &InstallHostAttachGateRequestV1| {
            decode_host_attach_gate_request_v1(
                &request.encode_to_vec(),
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
        };
        let mut request = request();
        request.original_ticket_binding_v2 =
            original_ticket(request.pending_grant.as_slice().try_into().unwrap());
        request.original_ticket_consume_v3 = [vec![20; 32], vec![21; 32]].concat();

        let decoded = decode(&request).unwrap();
        assert_eq!(
            decoded.original_ticket_consume_v3(),
            Some(([20; 32], [21; 32]))
        );
        assert_eq!(
            decoded.original_ticket_binding_v2(),
            Some(request.original_ticket_binding_v2.as_slice())
        );

        let mut absent_ticket = request.clone();
        absent_ticket.original_ticket_binding_v2.clear();
        assert!(decode(&absent_ticket).is_err());

        for correlation in [
            vec![1; 63],
            vec![1; 65],
            vec![0; 64],
            [vec![0; 32], vec![1; 32]].concat(),
            [vec![1; 32], vec![0; 32]].concat(),
        ] {
            let mut invalid = request.clone();
            invalid.original_ticket_consume_v3 = correlation;
            assert!(decode(&invalid).is_err());
        }

        let mut foreign = request;
        let mut foreign_grant: [u8; 416] = foreign.pending_grant.as_slice().try_into().unwrap();
        foreign_grant[415] ^= 1;
        foreign.original_ticket_binding_v2 = original_ticket(foreign_grant);
        assert!(decode(&foreign).is_err());
    }

    #[test]
    fn original_control_requires_ticket_canonical_request_and_exclusive_version() {
        let decode = |request: &InstallHostAttachGateRequestV1| {
            decode_host_attach_gate_request_v1(
                &request.encode_to_vec(),
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
        };
        let mut request = request();
        request.original_ticket_binding_v2 =
            original_ticket(request.pending_grant.as_slice().try_into().unwrap());
        let control = aos_sandbox_agent::openssh_control::OpenSshControlRequestV5 {
            sequence: 7,
            action: aos_sandbox_agent::openssh_control::OpenSshControlActionV5::Signal(15),
        }
        .encode()
        .unwrap();
        request.original_session_control_v5 =
            [vec![20; 32], vec![21; 32], control.clone()].concat();
        let valid = decode(&request).unwrap();
        assert_eq!(
            valid.original_session_control_v5(),
            Some(([20; 32], [21; 32], control.as_slice()))
        );
        let mut missing = request.clone();
        missing.original_ticket_binding_v2.clear();
        assert!(decode(&missing).is_err());
        let mut crossed = request.clone();
        crossed.original_ticket_consume_v3 = [vec![20; 32], vec![21; 32]].concat();
        assert!(decode(&crossed).is_err());
        // An empty additive field preserves binding-only installation; it is
        // not a V5 control and cannot enter the original-session effect path.
        let mut binding_only = request.clone();
        binding_only.original_session_control_v5.clear();
        assert!(
            decode(&binding_only)
                .unwrap()
                .original_session_control_v5()
                .is_none()
        );

        for length in 1..request.original_session_control_v5.len() {
            let mut partial = request.clone();
            partial.original_session_control_v5.truncate(length);
            assert!(decode(&partial).is_err());
        }
        for index in [0, 32] {
            let mut zero = request.clone();
            zero.original_session_control_v5[index..index + 32].fill(0);
            assert!(decode(&zero).is_err());
        }
        let mut padding = request.clone();
        padding.original_session_control_v5[64 + 17] = 1;
        assert!(decode(&padding).is_err());
        let mut trailing = request;
        trailing.original_session_control_v5.push(0);
        assert!(decode(&trailing).is_err());
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

        let mut changed_readback = evidence.clone();
        changed_readback.signed_gate_readback[12] ^= 1;
        assert!(
            decode_host_attach_gate_evidence_v1(&changed_readback.encode_to_vec(), &request)
                .is_err()
        );

        let ticket = original_ticket(*request.pending_grant());
        let mut bound_request = request.clone();
        bound_request.original_ticket_binding_v2 = ticket.clone();
        assert!(
            decode_host_attach_gate_evidence_v1(&evidence.encode_to_vec(), &bound_request).is_err()
        );
        let mut bound = evidence.clone();
        bound.original_ticket_digest_v2 = Sha256::digest(&ticket).to_vec();
        let mut packet = b"AOSTGR02".to_vec();
        packet.extend_from_slice(&bound.original_ticket_digest_v2);
        packet.extend_from_slice(&(bound.signed_gate_readback.len() as u32).to_be_bytes());
        packet.extend_from_slice(&bound.signed_gate_readback);
        packet.extend_from_slice(&[0; 64]);
        bound.signed_ticket_readback_v2 = packet;
        assert!(
            decode_host_attach_gate_evidence_v1(&bound.encode_to_vec(), &bound_request).is_ok()
        );
        assert!(decode_host_attach_gate_evidence_v1(&bound.encode_to_vec(), &request).is_err());
        let mut substitution = bound.clone();
        substitution.original_ticket_digest_v2[0] ^= 1;
        assert!(
            decode_host_attach_gate_evidence_v1(&substitution.encode_to_vec(), &bound_request)
                .is_err()
        );
        substitution = bound;
        substitution.signed_ticket_readback_v2[40..44].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(
            decode_host_attach_gate_evidence_v1(&substitution.encode_to_vec(), &bound_request)
                .is_err()
        );
    }

    #[test]
    fn read_only_queries_require_canonical_nonzero_evidence() {
        let peer = PeerCredentials {
            uid: 100,
            gid: 101,
            pid: Some(102),
        };
        let policy = PeerPolicy {
            uid: 100,
            gid: Some(101),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };
        let header = request().header.as_option().cloned().unwrap();
        let readiness_request = QueryHostAttachGateReadinessRequestV1 {
            header: Some(header.clone()).into(),
            ..Default::default()
        };
        assert!(
            decode_host_attach_readiness_request_v1(
                &readiness_request.encode_to_vec(),
                peer,
                policy,
                10,
            )
            .is_ok()
        );

        let readiness = HostAttachGateReadinessV1 {
            session_binding: vec![1; 32],
            incarnation_id: vec![2; 16],
            assignment_epoch: 3,
            assignment_digest: vec![4; 32],
            lease_generation: 5,
            lease_digest: vec![6; 32],
            trust_digest: vec![7; 32],
            ..Default::default()
        };
        assert!(decode_host_attach_readiness_v1(&readiness.encode_to_vec()).is_ok());
        let mut missing_lease = readiness;
        missing_lease.lease_digest.fill(0);
        assert!(decode_host_attach_readiness_v1(&missing_lease.encode_to_vec()).is_err());

        let route_query = QueryHostAttachGateRouteRequestV1 {
            header: Some(header).into(),
            operation_id: vec![8; 16],
            execution_id: vec![9; 16],
            ..Default::default()
        };
        assert!(
            decode_host_attach_route_query_v1(&route_query.encode_to_vec(), peer, policy, 10)
                .is_ok()
        );
        let mut missing_operation = route_query;
        missing_operation.operation_id.fill(0);
        assert!(
            decode_host_attach_route_query_v1(
                &missing_operation.encode_to_vec(),
                peer,
                policy,
                10,
            )
            .is_err()
        );
    }
}
