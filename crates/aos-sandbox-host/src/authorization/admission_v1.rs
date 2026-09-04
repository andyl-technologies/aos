//! Host adapter for shared signed-plan and ownership-lease admission.

use std::path::Path;

use aos_sandbox_broker::{
    AdmissionRequest, BrokerAdmissionError, BrokerAuthority, BrokerAuthorityConfigError,
    BrokerAuthorizationFenceV1, BrokerDomain, BrokerEffectIntentV2, VerifiedBrokerAdmission,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerPlanTrustAnchor, DesiredGeneration,
    IncarnationId, NodeId, ObjectDigest, OwnershipLeaseTrustAnchor, ProtocolId, ProtocolVersion,
    RawPairedClockSample, SandboxId,
};
use aos_sandbox_protocol::ValidatedRuntimeRequest;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;

use super::semantics_v1::canonical_host_semantics_v1;

/// Host-audience alias for shared admission failures.
pub type HostAdmissionError = BrokerAdmissionError;
/// Host-audience alias for protected authority configuration failures.
pub type HostAuthorityConfigError = BrokerAuthorityConfigError;
/// Exact authenticated records the host broker commits atomically.
pub(crate) type VerifiedHostAdmissionV1 = VerifiedBrokerAdmission;

/// Owns protected host-audience trust and durable authentication state.
pub struct HostAuthorityV1(BrokerAuthority);

impl HostAuthorityV1 {
    /// Constructs host authority from already validated protected anchors.
    ///
    /// # Errors
    ///
    /// Returns [`HostAdmissionError::InvalidConfiguration`] for invalid local
    /// node or journal-key configuration.
    pub fn new(
        plan_anchor: BrokerPlanTrustAnchor,
        lease_anchor: OwnershipLeaseTrustAnchor,
        node: NodeId,
        journal_key_id: [u8; 16],
        journal_secret: [u8; 32],
    ) -> Result<Self, HostAdmissionError> {
        BrokerAuthority::new(
            BrokerDomain::Host,
            plan_anchor,
            lease_anchor,
            node,
            journal_key_id,
            journal_secret,
        )
        .map(Self)
    }

    /// Loads host authority from a protected systemd credential directory.
    ///
    /// # Errors
    ///
    /// Returns [`HostAuthorityConfigError`] for any missing, insecure,
    /// malformed, oversized, or inconsistent credential.
    pub fn from_protected_directory(
        path: impl AsRef<Path>,
    ) -> Result<Self, HostAuthorityConfigError> {
        BrokerAuthority::from_protected_directory(path, BrokerDomain::Host).map(Self)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the adapter receives one closed host request plus protected context"
    )]
    pub(crate) fn admit(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &ValidatedRuntimeRequest,
        request_body: &[u8],
        protocol_version: ProtocolVersion,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        let semantics = canonical_host_semantics_v1(request)
            .map_err(|_| HostAdmissionError::RequestMismatch)?;
        self.0.admit(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Host,
                protocol: ProtocolId::HostBroker,
                protocol_version,
                assignment: request_assignment(request)?,
                request_id: *request.header().request_id(),
                request_body,
                descriptor_count: 0,
                verb: semantics.verb(),
                target: semantics.target(),
                argument_commitment: semantics.commitment(),
                request_deadline_boottime_nanoseconds: request
                    .header()
                    .deadline_boottime_nanoseconds(),
            },
            current_clock,
            prior_fence,
        )
    }

    pub(crate) fn open_effect(
        &self,
        request_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerEffectIntentV2, HostAdmissionError> {
        self.0.open_effect(request_id, bytes)
    }

    pub(crate) fn open_fence(
        &self,
        sandbox_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, HostAdmissionError> {
        self.0.open_fence(sandbox_id, bytes)
    }

    pub(crate) fn check_before_effect<F>(
        &self,
        effect: &BrokerEffectIntentV2,
        trusted_clock: &mut F,
    ) -> Result<(), HostAdmissionError>
    where
        F: FnMut() -> Result<RawPairedClockSample, HostAdmissionError>,
    {
        self.0.check_before_effect(effect, trusted_clock)
    }

    pub(crate) fn seal_fence(
        &self,
        sandbox_id: &[u8; 16],
        fence: &aos_sandbox_broker::BrokerAuthorizationFenceV1,
    ) -> Result<Vec<u8>, HostAdmissionError> {
        self.0.seal_fence(sandbox_id, fence)
    }

    pub(crate) fn seal_effect(
        &self,
        request_id: &[u8; 16],
        effect: &BrokerEffectIntentV2,
    ) -> Result<Vec<u8>, HostAdmissionError> {
        self.0.seal_effect(request_id, effect)
    }
}

fn request_assignment(
    request: &ValidatedRuntimeRequest,
) -> Result<BrokerAssignment, HostAdmissionError> {
    BrokerAssignment::new(
        SandboxId::from_bytes(*request.fence().sandbox_id()),
        IncarnationId::from_bytes(*request.fence().incarnation_id()),
        AssignmentEpoch::new(request.fence().assignment_epoch()),
        DesiredGeneration::new(request.fence().desired_generation()),
        ObjectDigest::from_bytes(*request.fence().assignment_digest()),
    )
    .map_err(|_| HostAdmissionError::RequestMismatch)
}
