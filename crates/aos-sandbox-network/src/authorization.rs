//! Network-audience adapter for shared signed authority admission.

use std::path::Path;

use aos_proto::aos::sandbox::local::v1::ApplyNetworkRequest;
use aos_sandbox::RecordNamespace;
use aos_sandbox_broker::{
    AdmissionRequest, BrokerAdmissionError, BrokerAuthority, BrokerAuthorityConfigError,
    BrokerDomain, BrokerLocalRecordDomain, VerifiedBrokerAdmission,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerPlanTrustAnchor, DesiredGeneration,
    IncarnationId, NodeId, ObjectDigest, OwnershipLeaseTrustAnchor, ProtocolId, ProtocolVersion,
    RawPairedClockSample, SandboxId,
};
use aos_sandbox_protocol::semantics::network::CanonicalNetworkSemanticsV1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use buffa::Message as _;

use crate::catalog::{
    AuthenticatedNetworkPreparationV1, ResolvedNetworkPreparationV1, encode_resolution,
};

fn catalog_domain() -> Result<BrokerLocalRecordDomain, NetworkAdmissionError> {
    BrokerLocalRecordDomain::new(*b"AOSNETCATALOG001")
        .map_err(|_| NetworkAdmissionError::InvalidConfiguration)
}

/// Network authority configuration failure.
pub type NetworkAuthorityConfigError = BrokerAuthorityConfigError;
/// Network signed admission failure.
pub type NetworkAdmissionError = BrokerAdmissionError;

/// Owns protected Network-audience trust and journal authentication.
pub struct NetworkAuthorityV1(pub(crate) BrokerAuthority);

impl NetworkAuthorityV1 {
    /// Constructs authority from protected trust anchors.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkAdmissionError::InvalidConfiguration`] for sentinels.
    pub fn new(
        plan: BrokerPlanTrustAnchor,
        lease: OwnershipLeaseTrustAnchor,
        node: NodeId,
        key_id: [u8; 16],
        secret: [u8; 32],
    ) -> Result<Self, NetworkAdmissionError> {
        BrokerAuthority::new(BrokerDomain::Network, plan, lease, node, key_id, secret).map(Self)
    }

    /// Loads authority from the shared protected fixed-file schema.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkAuthorityConfigError`] for insecure or invalid credentials.
    pub fn from_protected_directory(
        path: impl AsRef<Path>,
    ) -> Result<Self, NetworkAuthorityConfigError> {
        BrokerAuthority::from_protected_directory(path, BrokerDomain::Network).map(Self)
    }

    // Only a future root-owned catalog publisher in this crate may call this.
    // Keeping it crate-private prevents callers from blessing arbitrary local
    // identities merely because they can submit broker requests.
    #[cfg(test)]
    pub(crate) fn authenticate_protected_catalog(
        &self,
        resolution: ResolvedNetworkPreparationV1,
    ) -> Result<AuthenticatedNetworkPreparationV1, NetworkAdmissionError> {
        let payload = encode_resolution(&resolution);
        let sealed = self.0.seal_local_record(
            RecordNamespace::DesiredState,
            resolution.binding().digest().as_bytes(),
            catalog_domain()?,
            &payload,
        )?;
        Ok(AuthenticatedNetworkPreparationV1 { resolution, sealed })
    }

    pub(crate) fn validate_catalog<'a>(
        &self,
        catalog: &'a AuthenticatedNetworkPreparationV1,
    ) -> Result<&'a ResolvedNetworkPreparationV1, NetworkAdmissionError> {
        let payload = self.0.open_local_record(
            RecordNamespace::DesiredState,
            catalog.resolution.binding().digest().as_bytes(),
            catalog_domain()?,
            &catalog.sealed,
        )?;
        if payload != encode_resolution(&catalog.resolution) {
            return Err(NetworkAdmissionError::RequestMismatch);
        }
        Ok(&catalog.resolution)
    }

    pub(crate) fn admit(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        semantics: &CanonicalNetworkSemanticsV1,
        body: &[u8],
        version: ProtocolVersion,
        clock: &RawPairedClockSample,
        prior: Option<&[u8]>,
    ) -> Result<VerifiedBrokerAdmission, NetworkAdmissionError> {
        let assignment = decode_assignment(body)?;
        let admission = self.0.admit(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Network,
                protocol: ProtocolId::NetworkBroker,
                protocol_version: version,
                assignment,
                request_id: *semantics.header().request_id(),
                request_body: body,
                descriptor_count: 0,
                verb: semantics.broker_verb(),
                target: semantics.grant_target(),
                argument_commitment: semantics.argument_commitment(),
                request_deadline_boottime_nanoseconds: semantics
                    .header()
                    .deadline_boottime_nanoseconds(),
            },
            clock,
            prior,
        )?;
        if let Some((digest, generation)) = semantics.operation().ownership_lease() {
            let local = admission.fence.local_lease_record();
            if admission.effect.lease_digest().as_bytes() != digest
                || local.lease_generation() != generation
                || Some(local.fail_stop_boottime_nanoseconds())
                    != semantics.operation().fail_stop_boottime_nanoseconds()
            {
                return Err(NetworkAdmissionError::RequestMismatch);
            }
        }
        Ok(admission)
    }

    pub(crate) fn seal_fence(
        &self,
        sandbox_id: &[u8; 16],
        admission: &VerifiedBrokerAdmission,
    ) -> Result<Vec<u8>, NetworkAdmissionError> {
        self.0.seal_fence(sandbox_id, &admission.fence)
    }

    pub(crate) fn seal_effect(
        &self,
        request_id: &[u8; 16],
        admission: &VerifiedBrokerAdmission,
    ) -> Result<Vec<u8>, NetworkAdmissionError> {
        self.0.seal_effect(request_id, &admission.effect)
    }

    pub(crate) fn seal_local(
        &self,
        request_id: &[u8; 16],
        domain: BrokerLocalRecordDomain,
        payload: &[u8],
    ) -> Result<Vec<u8>, NetworkAdmissionError> {
        self.0
            .seal_local_record(RecordNamespace::Operation, request_id, domain, payload)
    }

    pub(crate) fn open_local<'a>(
        &self,
        request_id: &[u8; 16],
        domain: BrokerLocalRecordDomain,
        bytes: &'a [u8],
    ) -> Result<&'a [u8], NetworkAdmissionError> {
        self.0
            .open_local_record(RecordNamespace::Operation, request_id, domain, bytes)
    }

    pub(crate) fn validate_links(
        &self,
        sandbox_id: &[u8; 16],
        request_id: &[u8; 16],
        fence: &[u8],
        effect: &[u8],
    ) -> Result<aos_sandbox_broker::BrokerEffectIntentV2, NetworkAdmissionError> {
        let opened_fence = self.0.open_fence(sandbox_id, fence)?;
        let opened_effect = self.0.open_effect(request_id, effect)?;
        let lease = opened_fence.local_lease_record();
        if opened_fence.assignment().sandbox().as_bytes() != sandbox_id
            || opened_effect.plan_digest() != opened_fence.plan_digest()
            || opened_effect.lease_digest() != lease.lease_digest()
            || opened_effect.host_boot_id() != lease.host_boot_id()
            || opened_effect.clock_provenance() != lease.clock_provenance()
        {
            return Err(NetworkAdmissionError::FenceRejected);
        }
        Ok(opened_effect)
    }

    pub(crate) fn open_fence(
        &self,
        sandbox_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<aos_sandbox_broker::BrokerAuthorizationFenceV1, NetworkAdmissionError> {
        self.0.open_fence(sandbox_id, bytes)
    }
}

pub(crate) fn decode_assignment(body: &[u8]) -> Result<BrokerAssignment, NetworkAdmissionError> {
    let request = ApplyNetworkRequest::decode_from_slice(body)
        .map_err(|_| NetworkAdmissionError::RequestMismatch)?;
    let fence = request
        .fence
        .as_option()
        .ok_or(NetworkAdmissionError::RequestMismatch)?;
    BrokerAssignment::new(
        SandboxId::from_bytes(
            fence
                .sandbox_id
                .as_slice()
                .try_into()
                .map_err(|_| NetworkAdmissionError::RequestMismatch)?,
        ),
        IncarnationId::from_bytes(
            fence
                .incarnation_id
                .as_slice()
                .try_into()
                .map_err(|_| NetworkAdmissionError::RequestMismatch)?,
        ),
        AssignmentEpoch::new(fence.assignment_epoch),
        DesiredGeneration::new(fence.desired_generation),
        ObjectDigest::from_bytes(
            fence
                .assignment_digest
                .as_slice()
                .try_into()
                .map_err(|_| NetworkAdmissionError::RequestMismatch)?,
        ),
    )
    .map_err(|_| NetworkAdmissionError::RequestMismatch)
}
