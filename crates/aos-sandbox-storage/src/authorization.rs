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
    BrokerAuthorizationFenceV1, BrokerDomain, BrokerEffectIntentV2,
    ProtectedBrokerAuthorityConfiguration, VerifiedBrokerAdmission,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerPlanTrustAnchor, DesiredGeneration,
    IncarnationId, NodeId, ObjectDigest, OwnershipLeaseTrustAnchor, ProtocolId, ProtocolVersion,
    RawPairedClockSample, SandboxId,
};
use aos_sandbox_protocol::semantics::storage::CanonicalStorageSemanticsV1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use buffa::Message as _;

use crate::StorageStateKey;

/// Storage-audience alias for protected authority configuration failures.
pub type StorageAuthorityConfigError = BrokerAuthorityConfigError;
/// Storage-audience alias for signed admission failures.
pub type StorageAdmissionError = BrokerAdmissionError;

/// Couples Storage authority and durable-state authentication from one read.
///
/// The protected directory remains a restart-time configuration boundary. It
/// must be provisioned completely before startup rather than edited in place.
pub struct StorageProtectedConfigurationV1 {
    authority: StorageAuthorityV1,
    state_key: StorageStateKey,
    public_binding: ObjectDigest,
}

impl StorageProtectedConfigurationV1 {
    /// Loads Storage authority and its matching state key together.
    ///
    /// # Errors
    ///
    /// Returns [`StorageAuthorityConfigError`] when protected configuration is
    /// missing, insecure, malformed, oversized, or internally inconsistent.
    pub fn from_protected_directory(
        path: impl AsRef<Path>,
    ) -> Result<Self, StorageAuthorityConfigError> {
        let configuration = ProtectedBrokerAuthorityConfiguration::from_protected_directory(
            path,
            BrokerDomain::Storage,
        )?;
        let public_binding = configuration.public_binding();
        let (authority, key_id, secret) = configuration.into_parts();
        let state_key = StorageStateKey::new(key_id, *secret)
            .map_err(|_| StorageAuthorityConfigError::Invalid("journal-mac-key"))?;

        Ok(Self {
            authority: StorageAuthorityV1(authority),
            state_key,
            public_binding,
        })
    }

    /// Separates the coupled configuration for lifetime-owned runtime state.
    #[must_use]
    pub fn into_parts(self) -> (StorageAuthorityV1, StorageStateKey, ObjectDigest) {
        (self.authority, self.state_key, self.public_binding)
    }

    /// Returns the non-secret binding persisted with Storage runtime state.
    #[must_use]
    pub const fn public_binding(&self) -> ObjectDigest {
        self.public_binding
    }
}

/// Groups the three location-bound records committed with one Storage intent.
pub(crate) struct SealedStorageAdmission {
    pub(crate) current_fence: Vec<u8>,
    pub(crate) effect: Vec<u8>,
    pub(crate) operation_fence: Vec<u8>,
}

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
        operation_id: &[u8; 16],
        admission: &VerifiedBrokerAdmission,
    ) -> Result<SealedStorageAdmission, StorageAdmissionError> {
        Ok(SealedStorageAdmission {
            current_fence: self.0.seal_fence(sandbox_id, &admission.fence)?,
            effect: self.0.seal_effect(request_id, &admission.effect)?,
            operation_fence: self
                .0
                .seal_operation_fence(operation_id, &admission.fence)?,
        })
    }

    pub(crate) fn open_fence(
        &self,
        sandbox_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, StorageAdmissionError> {
        self.0.open_fence(sandbox_id, bytes)
    }

    pub(crate) fn open_operation_fence(
        &self,
        operation_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, StorageAdmissionError> {
        self.0.open_operation_fence(operation_id, bytes)
    }

    pub(crate) fn open_admission_intent(
        &self,
        request_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerEffectIntentV2, StorageAdmissionError> {
        self.0.open_effect(request_id, bytes)
    }

    pub(crate) fn check_before_effect<F>(
        &self,
        effect: &BrokerEffectIntentV2,
        trusted_clock: &mut F,
    ) -> Result<(), StorageAdmissionError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        self.0.check_before_effect(effect, trusted_clock)
    }

    pub(crate) fn check_current_fence(
        &self,
        fence: &BrokerAuthorizationFenceV1,
    ) -> Result<(), StorageAdmissionError> {
        self.0.check_current_fence(fence)
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
