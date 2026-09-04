//! Mount-specific adapter for common signed broker admission.

use std::path::Path;

use aos_proto::aos::sandbox::local::v1::BrokerDescriptorRole;
use aos_sandbox_broker::{
    AdmissionRequest, BrokerAdmissionError, BrokerAuthority, BrokerAuthorityConfigError,
    BrokerDomain, BrokerEffectIntentV2, VerifiedBrokerAdmission,
};
use aos_sandbox_core::{
    BrokerAssignment, BrokerPlanTrustAnchor, DesiredGeneration, IncarnationId, NodeId,
    ObjectDigest, OwnershipLeaseTrustAnchor, ProtocolId, ProtocolVersion, RawPairedClockSample,
    SandboxId,
};
use aos_sandbox_protocol::ValidatedMountRequest;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;

use super::semantics_v1::{MountCatalogCommitmentV1, canonical_mount_semantics_v1};

/// Mount-audience alias for common broker admission failures.
pub type MountAdmissionError = BrokerAdmissionError;
/// Mount-audience alias for protected authority configuration failures.
pub type MountAuthorityConfigError = BrokerAuthorityConfigError;
/// Exact authenticated records the mount broker commits atomically.
pub(crate) type VerifiedMountAdmissionV1 = VerifiedBrokerAdmission;

/// Owns protected mount-audience trust and durable authentication state.
pub struct MountAuthorityV1(BrokerAuthority);

impl MountAuthorityV1 {
    /// Constructs mount authority from already validated protected anchors.
    ///
    /// # Errors
    ///
    /// Returns [`MountAdmissionError::InvalidConfiguration`] for invalid local
    /// node or journal key configuration.
    pub fn new(
        plan_anchor: BrokerPlanTrustAnchor,
        lease_anchor: OwnershipLeaseTrustAnchor,
        node: NodeId,
        journal_key_id: [u8; 16],
        journal_secret: [u8; 32],
    ) -> Result<Self, MountAdmissionError> {
        BrokerAuthority::new(
            BrokerDomain::Mount,
            plan_anchor,
            lease_anchor,
            node,
            journal_key_id,
            journal_secret,
        )
        .map(Self)
    }

    /// Loads mount authority from the common protected fixed-file schema.
    ///
    /// # Errors
    ///
    /// Returns [`MountAuthorityConfigError`] for an absent, insecure,
    /// malformed, oversized, or internally inconsistent authority file.
    pub fn from_protected_directory(
        path: impl AsRef<Path>,
    ) -> Result<Self, MountAuthorityConfigError> {
        BrokerAuthority::from_protected_directory(path, BrokerDomain::Mount).map(Self)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the adapter receives one closed mount request plus its protected context"
    )]
    pub(crate) fn admit(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &ValidatedMountRequest,
        request_body: &[u8],
        catalog: Option<MountCatalogCommitmentV1>,
        descriptor_roles: &[BrokerDescriptorRole],
        protocol_version: ProtocolVersion,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedMountAdmissionV1, MountAdmissionError> {
        let semantics = canonical_mount_semantics_v1(request, catalog, descriptor_roles)
            .map_err(|_| MountAdmissionError::RequestMismatch)?;
        let assignment = request_assignment(request)?;
        let descriptor_count = u16::try_from(descriptor_roles.len())
            .map_err(|_| MountAdmissionError::RequestMismatch)?;
        self.0.admit(
            artifacts,
            AdmissionRequest {
                audience: aos_sandbox_core::BrokerAudience::Mount,
                protocol: ProtocolId::MountBroker,
                protocol_version,
                assignment,
                request_id: *request.header().request_id(),
                request_body,
                descriptor_count,
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
    ) -> Result<BrokerEffectIntentV2, MountAdmissionError> {
        self.0.open_effect(request_id, bytes)
    }

    pub(crate) fn validate_effect_clock(
        &self,
        effect: &BrokerEffectIntentV2,
        current_clock: &RawPairedClockSample,
    ) -> Result<(), MountAdmissionError> {
        self.0.validate_effect_clock(effect, current_clock)
    }

    pub(crate) fn check_before_effect<F>(
        &self,
        effect: &BrokerEffectIntentV2,
        trusted_clock: &mut F,
    ) -> Result<(), MountAdmissionError>
    where
        F: FnMut() -> Result<RawPairedClockSample, MountAdmissionError>,
    {
        self.0.check_before_effect(effect, trusted_clock)
    }

    pub(crate) fn seal_fence(
        &self,
        sandbox_id: &[u8; 16],
        fence: &aos_sandbox_broker::BrokerAuthorizationFenceV1,
    ) -> Result<Vec<u8>, MountAdmissionError> {
        self.0.seal_fence(sandbox_id, fence)
    }

    pub(crate) fn seal_effect(
        &self,
        request_id: &[u8; 16],
        effect: &BrokerEffectIntentV2,
    ) -> Result<Vec<u8>, MountAdmissionError> {
        self.0.seal_effect(request_id, effect)
    }
}

fn request_assignment(
    request: &ValidatedMountRequest,
) -> Result<BrokerAssignment, MountAdmissionError> {
    BrokerAssignment::new(
        SandboxId::from_bytes(*request.fence().sandbox_id()),
        IncarnationId::from_bytes(*request.fence().incarnation_id()),
        aos_sandbox_core::AssignmentEpoch::new(request.fence().assignment_epoch()),
        DesiredGeneration::new(request.fence().desired_generation()),
        ObjectDigest::from_bytes(*request.fence().assignment_digest()),
    )
    .map_err(|_| MountAdmissionError::RequestMismatch)
}
