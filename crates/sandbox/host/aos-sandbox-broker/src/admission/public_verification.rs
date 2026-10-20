//! Shares signature verification with a public-only Network read admission.
//!
//! This verifier owns no journal MAC key and cannot seal a fence, derive a
//! local lease or issue an effect. Native Source and original-record custody
//! must qualify the supplied completed lease before its read result is used.

use super::*;

pub(super) struct PublicVerificationInputsV2<'held> {
    plan_anchor: &'held BrokerPlanTrustAnchor,
    lease_anchor: &'held OwnershipLeaseTrustAnchor,
    node: NodeId,
}

impl BrokerAuthority {
    pub(super) fn public_verification_v2(&self) -> PublicVerificationInputsV2<'_> {
        PublicVerificationInputsV2 {
            plan_anchor: &self.plan_anchor,
            lease_anchor: &self.lease_anchor,
            node: self.node,
        }
    }
}

impl PublicVerificationInputsV2<'_> {
    pub(super) fn verify_signed_plan_retaining_v4(
        &self,
        artifacts: aos_sandbox_protocol::session::AuthorizationArtifactBytes<'_>,
        request: &AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        mut original: Option<&mut BrokerSignedAdmissionOriginalV4>,
    ) -> Result<aos_sandbox_model::VerifiedBrokerPlan, BrokerAdmissionError> {
        let plan_signature = decode_signature(
            artifacts.broker_plan_signature,
            artifact_limits(MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES),
        )
        .map_err(|cause| {
            if let Some(original) = original.as_deref_mut() {
                original.retain_canonical_v4(cause);
            }
            BrokerAdmissionError::VerificationFailed
        })?;
        let verified_plan = verify_broker_plan(
            artifacts.broker_plan,
            &plan_signature,
            self.plan_anchor,
            BrokerPlanExpectation {
                audience: request.audience,
                protocol: request.protocol,
                protocol_version: request.protocol_version,
                assignment: request.assignment,
                node: self.node,
                now_seconds: current_clock.wall_seconds(),
            },
            artifact_limits(MAXIMUM_BROKER_PLAN_BYTES),
        )
        .map_err(|cause| {
            if let Some(original) = original.as_deref_mut() {
                original.retain_plan_v4(cause);
            }
            BrokerAdmissionError::VerificationFailed
        })?;
        Ok(verified_plan)
    }

    pub(super) fn verify_signed_lease_retaining_v4(
        &self,
        artifacts: aos_sandbox_protocol::session::AuthorizationArtifactBytes<'_>,
        verified_plan: &aos_sandbox_model::VerifiedBrokerPlan,
        request: &AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        mut original: Option<&mut BrokerSignedAdmissionOriginalV4>,
    ) -> Result<VerifiedOwnershipLease, BrokerAdmissionError> {
        let lease_signature = decode_signature(
            artifacts.ownership_lease_signature,
            artifact_limits(MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES),
        )
        .map_err(|cause| {
            if let Some(original) = original.as_deref_mut() {
                original.retain_canonical_v4(cause);
            }
            BrokerAdmissionError::VerificationFailed
        })?;
        let verified_lease = verify_ownership_lease(
            artifacts.ownership_lease,
            &lease_signature,
            self.lease_anchor,
            OwnershipLeaseExpectation {
                assignment: request.assignment,
                node: self.node,
                ownership_authority: verified_plan.plan().ownership_authority(),
                clock: current_clock,
            },
            artifact_limits(MAXIMUM_OWNERSHIP_LEASE_BYTES),
        )
        .map_err(|cause| {
            if let Some(original) = original.as_deref_mut() {
                original.retain_lease_v4(cause);
            }
            BrokerAdmissionError::VerificationFailed
        })?;

        Ok(verified_lease)
    }
}

/// Owns only the existing public Network plan and ownership verification pins.
///
/// The native six-credential receiver is the sole constructor. This object has
/// no signer or journal key. Its cryptographic result is not a Source/F loan,
/// completed local-lease provenance, worker permit or mutation authorization.
pub struct NetworkPublicVerifierV2 {
    plan_anchor: BrokerPlanTrustAnchor,
    lease_anchor: OwnershipLeaseTrustAnchor,
    node: NodeId,
}

impl NetworkPublicVerifierV2 {
    pub(crate) fn from_captured_anchors_v2(
        plan_anchor: BrokerPlanTrustAnchor,
        lease_anchor: OwnershipLeaseTrustAnchor,
        node: NodeId,
    ) -> Result<Self, BrokerAdmissionError> {
        if node.as_bytes() == &[0; 16] {
            return Err(BrokerAdmissionError::InvalidConfiguration);
        }
        Ok(Self {
            plan_anchor,
            lease_anchor,
            node,
        })
    }

    fn inputs(&self) -> PublicVerificationInputsV2<'_> {
        PublicVerificationInputsV2 {
            plan_anchor: &self.plan_anchor,
            lease_anchor: &self.lease_anchor,
            node: self.node,
        }
    }

    /// Quotes the same signature and intersection recipe on these public pins.
    ///
    /// # Errors
    /// Refuses arithmetic overflow in the existing conservative crypto quote.
    pub fn receiving_demand_v2(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
    ) -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError> {
        super::receiving::public_verification_receiving_demand_v2(
            &self.plan_anchor,
            &self.lease_anchor,
            artifacts,
        )
    }

    /// Verifies a Network read against the handed-off original completed lease.
    ///
    /// This calls the ordinary signature and intersection engine. It never
    /// calls `prepare_local_lease_record` or computes a replacement deadline.
    /// The actual native Source owner must independently attest both supplied
    /// fences/effect and retain the authenticated handoff through every read.
    ///
    /// # Errors
    /// Retains typed signature/intersection errors and refuses foreign purpose,
    /// changed original records, expiry, clock discontinuity or reentry.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_original_network_read_once_v2(
        &self,
        artifacts: aos_sandbox_protocol::session::AuthorizationArtifactBytes<'_>,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        current_fence: &BrokerAuthorizationFenceV1,
        operation_fence: &BrokerAuthorizationFenceV1,
        effect: &BrokerEffectIntentV1,
        original: &mut BrokerSignedAdmissionOriginalV4,
    ) -> Result<BrokerAdmissionIntersection, BrokerAdmissionError> {
        original.begin_public_read_once_v2()?;
        let result = self.verify_original_network_read_inner_v2(
            artifacts,
            request,
            current_clock,
            current_fence,
            operation_fence,
            effect,
            original,
        );
        original.finish_public_read_v2(result.as_ref().map(|_| ()).map_err(|cause| *cause));
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_original_network_read_inner_v2(
        &self,
        artifacts: aos_sandbox_protocol::session::AuthorizationArtifactBytes<'_>,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        current_fence: &BrokerAuthorizationFenceV1,
        operation_fence: &BrokerAuthorizationFenceV1,
        effect: &BrokerEffectIntentV1,
        original: &mut BrokerSignedAdmissionOriginalV4,
    ) -> Result<BrokerAdmissionIntersection, BrokerAdmissionError> {
        if request.audience != aos_sandbox_model::BrokerAudience::Network
            || request.protocol != ProtocolId::NetworkBroker
            || !supports_signed_admission(request.protocol, request.protocol_version)
            || !matches!(
                request.verb,
                BrokerVerb::NetworkPrepare | BrokerVerb::NetworkDestroy
            )
            || request.request_id == [0; 16]
            || request.request_body.is_empty()
            || request.request_deadline_boottime_nanoseconds <= current_clock.boottime_nanoseconds()
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let verification = self.inputs();
        let plan = verification.verify_signed_plan_retaining_v4(
            artifacts,
            &request,
            current_clock,
            Some(&mut *original),
        )?;
        let request_bytes = u32::try_from(request.request_body.len())
            .map_err(|_| BrokerAdmissionError::RequestMismatch)?;
        let matched = plan
            .match_request(BrokerPlanRequest {
                verb: request.verb,
                target: request.target,
                argument_commitment: request.argument_commitment,
                request_bytes,
                descriptor_count: request.descriptor_count,
            })
            .map_err(|cause| {
                original.retain_plan_v4(cause);
                BrokerAdmissionError::RequestMismatch
            })?;
        let lease = verification.verify_signed_lease_retaining_v4(
            artifacts,
            &plan,
            &request,
            current_clock,
            Some(&mut *original),
        )?;
        if current_fence != operation_fence
            || current_fence.assignment() != request.assignment
            || current_fence.node() != self.node
            || current_fence.plan_digest() != plan.plan_digest()
            || current_fence.plan_expires_seconds() != plan.plan().expires_seconds()
            || current_fence.ownership_authority() != self.lease_anchor.authority()
            || current_fence.ownership_authority() != plan.plan().ownership_authority()
            || effect.status() != BrokerEffectStatusV1::Pending
            || effect.local_lease_record() != operation_fence.local_lease_record()
            || effect.request_id() != &request.request_id
            || effect.transport_request_digest()
                != ObjectDigest::from_bytes(Sha256::digest(request.request_body).into())
            || effect.request_digest() != request.argument_commitment.digest()
            || effect.plan_digest() != plan.plan_digest()
            || effect.lease_digest() != lease.lease_digest()
            || effect.verb() != request.verb
            || effect.target() != request.target
            || effect.request_deadline_boottime_nanoseconds()
                != request.request_deadline_boottime_nanoseconds
        {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        let intersection = intersect_broker_admission(
            matched,
            &lease,
            operation_fence.local_lease_record(),
            current_clock,
            request.request_id,
            request.argument_commitment.digest(),
        )
        .map_err(|cause| {
            original.retain_lease_v4(cause);
            BrokerAdmissionError::FenceRejected
        })?;
        match BrokerEffectClockComparisonV3::from_effect(effect).classify(current_clock)? {
            BrokerEffectClockDispositionV1::Fresh => Ok(intersection),
            BrokerEffectClockDispositionV1::Expired => Err(BrokerAdmissionError::FenceRejected),
        }
    }
}
