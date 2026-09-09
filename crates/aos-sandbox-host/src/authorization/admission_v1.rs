//! Host adapter for shared signed-plan and ownership-lease admission.

use std::os::fd::BorrowedFd;
use std::path::Path;

use aos_sandbox_broker::{
    AdmissionRequest, BrokerAdmissionError, BrokerAuthority, BrokerAuthorityConfigError,
    BrokerAuthorizationFenceV1, BrokerDomain, BrokerEffectIntentV2, BrokerLocalRecordDomain,
    ProtectedBrokerAuthorityConfiguration, ProtectedBrokerPublicCredentialRole,
    ProtectedBrokerPublicCredentialSnapshot, ProtectedBrokerPublicCredentials, RecordNamespace,
    VerifiedBrokerAdmission,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerPlanTrustAnchor, DesiredGeneration,
    IncarnationId, NodeId, ObjectDigest, OwnershipLeaseTrustAnchor, ProtocolId, ProtocolVersion,
    RawPairedClockSample, SandboxId,
};
use aos_sandbox_protocol::ValidatedRuntimeRequest;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;

use super::semantics_v1::canonical_host_semantics_v1;

const HOST_EXECUTION_RECORD_DOMAIN: [u8; 16] = *b"AOSHOSTEXECV0001";

/// Host-audience alias for shared admission failures.
pub type HostAdmissionError = BrokerAdmissionError;
/// Host-audience alias for protected authority configuration failures.
pub type HostAuthorityConfigError = BrokerAuthorityConfigError;
/// Exact authenticated records the host broker commits atomically.
pub(crate) type VerifiedHostAdmissionV1 = VerifiedBrokerAdmission;

/// Owns protected host-audience trust and durable authentication state.
pub struct HostAuthorityV1 {
    authority: BrokerAuthority,
    public_credentials: Option<ProtectedBrokerPublicCredentials>,
}

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
        let authority = BrokerAuthority::new(
            BrokerDomain::Host,
            plan_anchor,
            lease_anchor,
            node,
            journal_key_id,
            journal_secret,
        )?;
        Ok(Self {
            authority,
            public_credentials: None,
        })
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
        let configuration = ProtectedBrokerAuthorityConfiguration::from_protected_directory(
            path,
            BrokerDomain::Host,
        )?;
        let (authority, public_credentials) = configuration.into_authority_and_public_credentials();
        Ok(Self {
            authority,
            public_credentials: Some(public_credentials),
        })
    }

    /// Revalidates and borrows the protected public Guardian credentials.
    ///
    /// Authorities built directly with [`Self::new`] have no descriptor
    /// custody and return `Ok(None)`. A protected-directory authority returns
    /// all six roles and their original non-secret snapshots only while every
    /// descriptor still matches the exact bytes and metadata used to construct
    /// the authority.
    ///
    /// # Errors
    ///
    /// Returns [`HostAuthorityConfigError`] after any in-place rewrite,
    /// replacement, unlink, permission change, or descriptor read failure.
    pub(crate) fn revalidated_guardian_credentials(
        &self,
    ) -> Result<
        Option<
            [(
                ProtectedBrokerPublicCredentialRole,
                BorrowedFd<'_>,
                ProtectedBrokerPublicCredentialSnapshot,
            ); 6],
        >,
        HostAuthorityConfigError,
    > {
        self.public_credentials
            .as_ref()
            .map(ProtectedBrokerPublicCredentials::revalidated_descriptor_evidence)
            .transpose()
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
        self.authority.admit(
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
        self.authority.open_effect(request_id, bytes)
    }

    /// Checks the exact signed payload-scope query against live ownership.
    ///
    /// The carrier's new method does not change the signed authority profile.
    /// The current assignment plan must already contain this query's distinct
    /// argument commitment; an ordinary runtime-observe grant is insufficient.
    pub(crate) fn admit_payload_scope(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &aos_sandbox_protocol::payload_scope::ValidatedPayloadScopeRequest,
        request_body: &[u8],
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        let semantics =
            aos_sandbox_protocol::semantics::payload_scope::canonical_payload_scope_semantics_v1(
                request,
            )
            .map_err(|_| HostAdmissionError::RequestMismatch)?;
        let fence = request.fence();
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes(*fence.sandbox_id()),
            IncarnationId::from_bytes(*fence.incarnation_id()),
            AssignmentEpoch::new(fence.assignment_epoch()),
            DesiredGeneration::new(fence.desired_generation()),
            ObjectDigest::from_bytes(*fence.assignment_digest()),
        )
        .map_err(|_| HostAdmissionError::RequestMismatch)?;

        self.authority.admit(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Host,
                protocol: ProtocolId::HostBroker,
                protocol_version: ProtocolVersion::new(1, 1),
                assignment,
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
            Some(prior_fence),
        )
    }

    pub(crate) fn open_fence(
        &self,
        sandbox_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, HostAdmissionError> {
        self.authority.open_fence(sandbox_id, bytes)
    }

    /// Admits only the distinct exact-scope RootMount observation commitment.
    pub(crate) fn admit_mount_scope(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &aos_sandbox_protocol::mount_scope::ValidatedMountScopeRequest,
        request_body: &[u8],
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedHostAdmissionV1, HostAdmissionError> {
        let semantics =
            aos_sandbox_protocol::semantics::mount_scope::canonical_mount_scope_semantics_v1(
                request,
            )
            .map_err(|_| HostAdmissionError::RequestMismatch)?;

        let fence = request.fence();
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes(*fence.sandbox_id()),
            IncarnationId::from_bytes(*fence.incarnation_id()),
            AssignmentEpoch::new(fence.assignment_epoch()),
            DesiredGeneration::new(fence.desired_generation()),
            ObjectDigest::from_bytes(*fence.assignment_digest()),
        )
        .map_err(|_| HostAdmissionError::RequestMismatch)?;

        self.authority.admit(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Host,
                protocol: ProtocolId::HostBroker,
                // The carrier is 1.3; the separately signed authority format
                // remains 1.1. The new canonical domain binds its semantics.
                protocol_version: ProtocolVersion::new(1, 1),
                assignment,
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
            Some(prior_fence),
        )
    }

    pub(crate) fn check_before_effect<F>(
        &self,
        effect: &BrokerEffectIntentV2,
        trusted_clock: &mut F,
    ) -> Result<(), HostAdmissionError>
    where
        F: FnMut() -> Result<RawPairedClockSample, HostAdmissionError>,
    {
        self.authority.check_before_effect(effect, trusted_clock)
    }

    pub(crate) fn seal_fence(
        &self,
        sandbox_id: &[u8; 16],
        fence: &aos_sandbox_broker::BrokerAuthorizationFenceV1,
    ) -> Result<Vec<u8>, HostAdmissionError> {
        self.authority.seal_fence(sandbox_id, fence)
    }

    pub(crate) fn seal_effect(
        &self,
        request_id: &[u8; 16],
        effect: &BrokerEffectIntentV2,
    ) -> Result<Vec<u8>, HostAdmissionError> {
        self.authority.seal_effect(request_id, effect)
    }

    /// Authenticates one Host execution payload at its exact request location.
    pub(crate) fn seal_execution_record(
        &self,
        request_id: &[u8; 16],
        payload: &[u8],
    ) -> Result<Vec<u8>, HostAdmissionError> {
        if request_id == &[0; 16] || payload.is_empty() {
            return Err(HostAdmissionError::FenceRejected);
        }
        self.authority.seal_local_record(
            RecordNamespace::HostExecution,
            request_id,
            execution_record_domain()?,
            payload,
        )
    }

    /// Authenticates one exact request-keyed Host execution record.
    pub(crate) fn open_execution_record<'a>(
        &self,
        request_id: &[u8; 16],
        bytes: &'a [u8],
    ) -> Result<&'a [u8], HostAdmissionError> {
        if request_id == &[0; 16] {
            return Err(HostAdmissionError::FenceRejected);
        }
        let payload = self.authority.open_local_record(
            RecordNamespace::HostExecution,
            request_id,
            execution_record_domain()?,
            bytes,
        )?;
        if payload.is_empty() {
            return Err(HostAdmissionError::FenceRejected);
        }
        Ok(payload)
    }
}

fn execution_record_domain() -> Result<BrokerLocalRecordDomain, HostAdmissionError> {
    BrokerLocalRecordDomain::new(HOST_EXECUTION_RECORD_DOMAIN)
        .map_err(|_| HostAdmissionError::InvalidConfiguration)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::format::encode_trust_policy;
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, SignaturePurpose, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        DecodeLimits, MediaType, PortableMediaType, RevocationScopeId, TrustScopeId,
        descriptor_for_bytes,
    };
    use ed25519_dalek::SigningKey;
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn key_reference(
        name: &str,
        generation: u64,
        usage: KeyUsage,
        key: &SigningKey,
    ) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(name.to_owned()).unwrap(),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn policy(
        scope: TrustScopeId,
        purpose: SignaturePurpose,
        key: KeyReference,
    ) -> (Vec<u8>, aos_sandbox_core::ObjectDescriptor) {
        let bytes =
            encode_trust_policy(&TrustPolicy::new(scope, purpose, vec![key], vec![]).unwrap());
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
            &bytes,
        );
        (bytes, descriptor)
    }

    fn authority() -> HostAuthorityV1 {
        let plan_key = SigningKey::from_bytes(&[11; 32]);
        let lease_key = SigningKey::from_bytes(&[12; 32]);
        let plan_scope = TrustScopeId::from_bytes([13; 16]);
        let lease_scope = TrustScopeId::from_bytes([14; 16]);
        let plan_signer = key_reference(
            "host-execution-plan",
            1,
            KeyUsage::BrokerAuthorization,
            &plan_key,
        );
        let lease_signer = key_reference(
            "host-execution-lease",
            1,
            KeyUsage::OwnershipLease,
            &lease_key,
        );
        let (plan_policy, plan_descriptor) = policy(
            plan_scope,
            SignaturePurpose::BrokerAuthorization,
            plan_signer.clone(),
        );
        let (lease_policy, lease_descriptor) = policy(
            lease_scope,
            SignaturePurpose::OwnershipLease,
            lease_signer.clone(),
        );
        let plan_anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
            plan_policy,
            plan_descriptor,
            plan_scope,
            plan_signer,
            plan_key.verifying_key().to_bytes(),
            RevocationScopeId::from_bytes([15; 16]),
            DecodeLimits::default(),
        )
        .unwrap();
        let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            lease_policy,
            lease_descriptor,
            lease_scope,
            lease_signer,
            lease_key.verifying_key().to_bytes(),
            DecodeLimits::default(),
        )
        .unwrap();

        HostAuthorityV1::new(
            plan_anchor,
            lease_anchor,
            NodeId::from_bytes([16; 16]),
            [17; 16],
            [18; 32],
        )
        .unwrap()
    }

    #[test]
    fn direct_authority_has_no_protected_descriptor_custody() {
        assert!(
            authority()
                .revalidated_guardian_credentials()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn execution_record_is_bound_to_host_domain_and_request_location() {
        let authority = authority();
        let request_id = [21; 16];
        let sealed = authority
            .seal_execution_record(&request_id, b"host execution")
            .unwrap();

        assert_eq!(
            authority
                .open_execution_record(&request_id, &sealed)
                .unwrap(),
            b"host execution"
        );
        assert!(authority.open_execution_record(&[22; 16], &sealed).is_err());
        assert!(
            authority
                .authority
                .open_local_record(
                    RecordNamespace::HostExecution,
                    &request_id,
                    BrokerLocalRecordDomain::new(*b"AOSHOSTEXECV0002").unwrap(),
                    &sealed,
                )
                .is_err()
        );
    }

    #[test]
    fn execution_record_rejects_tampering_and_invalid_bounds() {
        let authority = authority();
        let request_id = [23; 16];
        let mut tampered = authority
            .seal_execution_record(&request_id, b"host execution")
            .unwrap();
        let final_byte = tampered.last_mut().unwrap();
        *final_byte ^= 1;

        assert!(
            authority
                .open_execution_record(&request_id, &tampered)
                .is_err()
        );
        assert!(
            authority
                .seal_execution_record(&[0; 16], b"payload")
                .is_err()
        );
        assert!(authority.seal_execution_record(&request_id, b"").is_err());
        assert!(
            authority
                .open_execution_record(&[0; 16], &tampered)
                .is_err()
        );
        assert!(
            authority
                .seal_execution_record(&request_id, &vec![1; 2 * 1024 * 1024])
                .is_err()
        );
    }
}
