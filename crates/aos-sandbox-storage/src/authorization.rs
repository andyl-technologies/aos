//! Storage-audience adapter for shared protected authority admission.
//!
//! This module adds no storage trust rules of its own. It maps exact portable
//! storage semantics and the validated assignment carried by the protobuf into
//! the shared broker verifier, then seals its pending fence/effect records for
//! atomic persistence beside the storage transaction intent.

use std::path::Path;

use aos_proto::aos::sandbox::local::v1::ApplyStorageRequest;
use aos_sandbox_broker::{
    AdmissionRequest, BrokerAdmissionError, BrokerAuthority, BrokerAuthorityConfigError,
    BrokerAuthorizationFenceV1, BrokerDomain, BrokerEffectIntentV2, VerifiedBrokerAdmission,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerPlanTrustAnchor, DesiredGeneration,
    IncarnationId, NodeId, ObjectDigest, OwnershipLeaseTrustAnchor, ProtocolId, ProtocolVersion,
    RawPairedClockSample, SandboxId,
};
use aos_sandbox_protocol::semantics::storage::CanonicalStorageSemanticsV1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use buffa::Message as _;

/// Storage-audience alias for protected authority configuration failures.
pub type StorageAuthorityConfigError = BrokerAuthorityConfigError;
/// Storage-audience alias for signed admission failures.
pub type StorageAdmissionError = BrokerAdmissionError;

/// Owns protected storage-audience trust and record-authentication state.
pub struct StorageAuthorityV1(BrokerAuthority);

impl StorageAuthorityV1 {
    /// Constructs storage authority from validated protected anchors.
    ///
    /// # Errors
    ///
    /// Returns [`StorageAdmissionError::InvalidConfiguration`] for invalid
    /// node or journal-key configuration.
    pub fn new(
        plan_anchor: BrokerPlanTrustAnchor,
        lease_anchor: OwnershipLeaseTrustAnchor,
        node: NodeId,
        journal_key_id: [u8; 16],
        journal_secret: [u8; 32],
    ) -> Result<Self, StorageAdmissionError> {
        BrokerAuthority::new(
            BrokerDomain::Storage,
            plan_anchor,
            lease_anchor,
            node,
            journal_key_id,
            journal_secret,
        )
        .map(Self)
    }

    /// Loads storage authority from the protected fixed-file schema.
    ///
    /// # Errors
    ///
    /// Returns [`StorageAuthorityConfigError`] for missing, insecure,
    /// malformed, oversized, or inconsistent protected credentials.
    pub fn from_protected_directory(
        path: impl AsRef<Path>,
    ) -> Result<Self, StorageAuthorityConfigError> {
        BrokerAuthority::from_protected_directory(path, BrokerDomain::Storage).map(Self)
    }

    pub(crate) fn admit(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        semantics: &CanonicalStorageSemanticsV1,
        request_body: &[u8],
        protocol_version: ProtocolVersion,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedBrokerAdmission, StorageAdmissionError> {
        let assignment = decode_assignment(request_body)?;
        self.0.admit(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Storage,
                protocol: ProtocolId::StorageBroker,
                protocol_version,
                assignment,
                request_id: *semantics.header().request_id(),
                request_body,
                descriptor_count: 0,
                verb: semantics.broker_verb(),
                target: semantics.grant_target(),
                argument_commitment: semantics.argument_commitment(),
                request_deadline_boottime_nanoseconds: semantics
                    .header()
                    .deadline_boottime_nanoseconds(),
            },
            current_clock,
            prior_fence,
        )
    }

    pub(crate) fn seal(
        &self,
        sandbox_id: &[u8; 16],
        request_id: &[u8; 16],
        admission: &VerifiedBrokerAdmission,
    ) -> Result<(Vec<u8>, Vec<u8>), StorageAdmissionError> {
        Ok((
            self.0.seal_fence(sandbox_id, &admission.fence)?,
            self.0.seal_effect(request_id, &admission.effect)?,
        ))
    }

    pub(crate) fn open_fence(
        &self,
        sandbox_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, StorageAdmissionError> {
        self.0.open_fence(sandbox_id, bytes)
    }

    pub(crate) fn open_admission_intent(
        &self,
        request_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerEffectIntentV2, StorageAdmissionError> {
        self.0.open_effect(request_id, bytes)
    }
}

pub(crate) fn decode_assignment(
    request_body: &[u8],
) -> Result<BrokerAssignment, StorageAdmissionError> {
    let request = ApplyStorageRequest::decode_from_slice(request_body)
        .map_err(|_| StorageAdmissionError::RequestMismatch)?;
    let fence = request
        .fence
        .as_option()
        .ok_or(StorageAdmissionError::RequestMismatch)?;
    let sandbox_id: [u8; 16] = fence
        .sandbox_id
        .as_slice()
        .try_into()
        .map_err(|_| StorageAdmissionError::RequestMismatch)?;
    let incarnation_id: [u8; 16] = fence
        .incarnation_id
        .as_slice()
        .try_into()
        .map_err(|_| StorageAdmissionError::RequestMismatch)?;
    let assignment_digest: [u8; 32] = fence
        .assignment_digest
        .as_slice()
        .try_into()
        .map_err(|_| StorageAdmissionError::RequestMismatch)?;
    BrokerAssignment::new(
        SandboxId::from_bytes(sandbox_id),
        IncarnationId::from_bytes(incarnation_id),
        AssignmentEpoch::new(fence.assignment_epoch),
        DesiredGeneration::new(fence.desired_generation),
        ObjectDigest::from_bytes(assignment_digest),
    )
    .map_err(|_| StorageAdmissionError::RequestMismatch)
}
