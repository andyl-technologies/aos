//! Signed authority admission for controller-to-Mount source operations.
//!
//! This adapter accepts only live-validated public protocol requests and their
//! exact received bytes. It recomputes portable semantics locally and supplies
//! the common authority layer with a closed Mount 2.0, zero-descriptor request.
//! It does not inspect provider state, mutate source-acquisition storage, or
//! confer permission to cross an effect boundary before durable admission.

use std::os::fd::OwnedFd;

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod};
use aos_sandbox_broker::AdmissionRequest;
use aos_sandbox_core::{BrokerAudience, ProtocolId, ProtocolVersion, RawPairedClockSample};
use aos_sandbox_protocol::semantics::{
    CanonicalMountSourceAcquisitionSemanticsV1, canonical_acquire_mount_source_semantics_v1,
    canonical_release_mount_source_acquisition_semantics_v1,
};
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{
    LiveValidatedAcquireMountSourceRequest, LiveValidatedReleaseMountSourceAcquisitionRequest,
    ValidatedAssignmentFence, ValidatedBrokerRequestEnvelope, ValidatedHeader,
    mount_source_acquisition_request_digest_v1,
};

use super::admission_v1::{
    MountAdmissionError, MountAuthorityV1, VerifiedMountAdmissionV1, assignment,
};

const MOUNT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(2, 0);

impl MountAuthorityV1 {
    /// Intersects one exact source Acquire with protected Mount authority.
    ///
    /// The request must already have passed live peer, header, deadline,
    /// binding, and pre-catalog Create validation. This method independently
    /// binds that DTO to the exact received body, recomputes its nonauthorizing
    /// portable semantics, and requires both the validated envelope table and
    /// the actual received ancillary descriptor array to be empty.
    ///
    /// # Errors
    ///
    /// Returns [`MountAdmissionError`] for a body/DTO mismatch, a non-Mount-2.0
    /// controller header, invalid canonical semantics, rejected signed plan or
    /// lease, stale protected fence, or failed protected clock checks.
    #[allow(
        dead_code,
        reason = "consumed by the sealed source-acquisition transition partition"
    )]
    pub(crate) fn admit_acquire_source(
        &self,
        request: &LiveValidatedAcquireMountSourceRequest,
        envelope: &ValidatedBrokerRequestEnvelope,
        received_descriptors: &[OwnedFd],
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedMountAdmissionV1, MountAdmissionError> {
        let carrier = validate_exact_carrier(
            request.header(),
            request.request_digest(),
            BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
            envelope,
            received_descriptors,
        )?;
        let semantics = canonical_acquire_mount_source_semantics_v1(request.request())
            .map_err(|_| MountAdmissionError::RequestMismatch)?;

        self.admit_source_operation(
            carrier,
            request.header(),
            request.fence(),
            semantics,
            current_clock,
            prior_fence,
        )
    }

    /// Intersects one exact source Release with protected Mount authority.
    ///
    /// The request must already have passed live peer, header, deadline, fence,
    /// acquisition, revision, and predecessor-digest validation. This method
    /// independently binds the DTO to the exact received body, recomputes its
    /// resource-scoped semantics, and requires both the validated envelope
    /// table and the actual received ancillary descriptor array to be empty.
    ///
    /// # Errors
    ///
    /// Returns [`MountAdmissionError`] for a body/DTO mismatch, a non-Mount-2.0
    /// controller header, invalid canonical semantics, rejected signed plan or
    /// lease, stale protected fence, or failed protected clock checks.
    #[allow(
        dead_code,
        reason = "consumed by the sealed source-acquisition transition partition"
    )]
    pub(crate) fn admit_release_source(
        &self,
        request: &LiveValidatedReleaseMountSourceAcquisitionRequest,
        envelope: &ValidatedBrokerRequestEnvelope,
        received_descriptors: &[OwnedFd],
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedMountAdmissionV1, MountAdmissionError> {
        let carrier = validate_exact_carrier(
            request.header(),
            request.request_digest(),
            BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION,
            envelope,
            received_descriptors,
        )?;
        let semantics = canonical_release_mount_source_acquisition_semantics_v1(request.request())
            .map_err(|_| MountAdmissionError::RequestMismatch)?;

        self.admit_source_operation(
            carrier,
            request.header(),
            request.fence(),
            semantics,
            current_clock,
            prior_fence,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the adapter carries one exact request and its protected admission context"
    )]
    fn admit_source_operation(
        &self,
        carrier: ValidatedSourceEffectCarrier<'_>,
        header: &ValidatedHeader,
        fence: &ValidatedAssignmentFence,
        semantics: CanonicalMountSourceAcquisitionSemanticsV1,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedMountAdmissionV1, MountAdmissionError> {
        self.0.admit(
            carrier.artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Mount,
                protocol: ProtocolId::MountBroker,
                protocol_version: MOUNT_PROTOCOL_VERSION,
                assignment: assignment(fence)?,
                request_id: *header.request_id(),
                request_body: carrier.request_body,
                descriptor_count: carrier.descriptor_count,
                verb: semantics.verb(),
                target: semantics.target(),
                argument_commitment: semantics.commitment(),
                request_deadline_boottime_nanoseconds: header.deadline_boottime_nanoseconds(),
            },
            current_clock,
            prior_fence,
        )
    }
}

struct ValidatedSourceEffectCarrier<'a> {
    artifacts: &'a ValidatedUntrustedAuthorizationArtifacts,
    request_body: &'a [u8],
    descriptor_count: u16,
}

fn validate_exact_carrier<'a>(
    header: &ValidatedHeader,
    request_digest: aos_sandbox_core::ObjectDigest,
    expected_method: BrokerMethod,
    envelope: &'a ValidatedBrokerRequestEnvelope,
    received_descriptors: &[OwnedFd],
) -> Result<ValidatedSourceEffectCarrier<'a>, MountAdmissionError> {
    let descriptor_count = u16::try_from(received_descriptors.len())
        .map_err(|_| MountAdmissionError::RequestMismatch)?;
    if header.protocol_version() != MOUNT_PROTOCOL_VERSION
        || header.audience() != Audience::AUDIENCE_NODE_CONTROLLER
        || envelope.method() != expected_method
        || mount_source_acquisition_request_digest_v1(envelope.body()) != request_digest
        || envelope.descriptors().len() != received_descriptors.len()
        || descriptor_count != 0
    {
        return Err(MountAdmissionError::RequestMismatch);
    }

    let artifacts = envelope
        .authorization()
        .ok_or(MountAdmissionError::RequestMismatch)?;
    Ok(ValidatedSourceEffectCarrier {
        artifacts,
        request_body: envelope.body(),
        descriptor_count,
    })
}
