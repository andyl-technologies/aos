//! Retains typed signed-admission errors without retaining pure decode scratch.
//!
//! The raw signed request remains in its receiving owner. Temporary decoded
//! plans, public keys and crypto models own no native obligations and may drop
//! after their prepaid interval. This header preserves their actual typed
//! source error and the once/result bookkeeping across the coarse API result.

use super::*;

#[derive(Debug, thiserror::Error)]
enum SourceErrorV4 {
    #[error("signed admission canonical decoding failed: {0}")]
    Canonical(#[source] aos_sandbox_core::CanonicalCborError),
    #[error("signed admission plan verification failed: {0}")]
    Plan(#[source] aos_sandbox_core::BrokerPlanVerificationError),
    #[error("signed admission ownership verification failed: {0}")]
    Lease(#[source] aos_sandbox_core::OwnershipLeaseVerificationError),
    #[error("signed admission protected record failed: {0}")]
    Record(#[source] AuthorizationRecordError),
}

/// Retains a selected Mount62, Network63, HostQuery27, HostPrepare58 or HostStop refusal.
///
/// Empty construction performs no verification or IO. The actual receiver
/// prepays `BrokerAuthority::signed_admission_receiving_demand_v4` before entry.
/// Returned admissions still require the ordinary durable fence and effect
/// checks; this diagnostic owner grants no native operation.
#[derive(Default)]
pub struct BrokerSignedAdmissionOriginalV4 {
    entered: bool,
    source: Option<SourceErrorV4>,
    result: Option<Result<(), BrokerAdmissionError>>,
    closed: Option<BrokerAdmissionError>,
}

impl BrokerSignedAdmissionOriginalV4 {
    pub(super) fn begin_public_read_once_v2(&mut self) -> Result<(), BrokerAdmissionError> {
        if self.entered {
            self.closed.get_or_insert(BrokerAdmissionError::RequestMismatch);
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.entered = true;
        Ok(())
    }

    pub(super) fn finish_public_read_v2(&mut self, result: Result<(), BrokerAdmissionError>) {
        self.result = Some(result);
    }

    /// Constructs an inert error header without allocation, verification or IO.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Runs the same ordinary admission engine while retaining typed errors.
    ///
    /// # Errors
    /// Rejects reentry, another role/purpose, or any ordinary signed admission
    /// failure. A refusal remains sticky and cannot be retried with new DATA.
    pub fn admit_once_v4(
        &mut self,
        authority: &BrokerAuthority,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        let selected = matches!((authority.domain, request.verb),
            (BrokerDomain::Mount, BrokerVerb::MountMaterializeAttachmentAnchor | BrokerVerb::MountReapAttachmentAnchor)
            | (BrokerDomain::Network, BrokerVerb::NetworkPrepare));
        self.admit_base_once_v4(authority, artifacts, request, current_clock, prior_fence, selected)
    }

    /// Retains one fresh Host Stop admission under the ordinary base-plan law.
    ///
    /// This port preserves the existing Stop fence and plan-rotation semantics.
    /// It does not adopt transport authentication as effect permission or accept
    /// the exact-grant rotation used by execution preparation and queries.
    ///
    /// # Errors
    /// Retains the original typed refusal for a foreign domain or verb,
    /// reentry, or any ordinary signed Stop admission failure.
    pub fn admit_host_stop_once_v4(
        &mut self,
        authority: &BrokerAuthority,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        let selected = authority.domain == BrokerDomain::Host
            && request.verb == BrokerVerb::HostStop;
        self.admit_base_once_v4(authority, artifacts, request, current_clock, prior_fence, selected)
    }

    fn admit_base_once_v4(
        &mut self,
        authority: &BrokerAuthority,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
        selected: bool,
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.entered {
            self.closed.get_or_insert(BrokerAdmissionError::RequestMismatch);
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.entered = true;
        if !selected {
            self.result = Some(Err(BrokerAdmissionError::RequestMismatch));
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let outcome = authority.admit_with_plan_rotation_retaining_v4(
            artifacts, request, current_clock, prior_fence, AdmissionPhase::BasePlan, Some(self),
        );
        self.result = Some(outcome.as_ref().map(|_| ()).map_err(|cause| *cause));
        outcome
    }

    /// Retains one exact HostQueryExecution admission on the existing engine.
    ///
    /// The ordinary prior base-plan fence remains the lease head. This port
    /// accepts only the Host read verb and cannot issue an execution effect.
    ///
    /// # Errors
    /// Keeps the first typed decoder, verification or record refusal on
    /// reentry, a foreign domain/verb, or ordinary exact-grant rejection.
    pub fn admit_host_query_once_v3(
        &mut self,
        authority: &BrokerAuthority,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        self.admit_host_exact_once_v5(authority, artifacts, request, current_clock,
            prior_fence, BrokerVerb::HostQueryExecution)
    }

    /// Retains only the actual method58 next-execution preparation admission.
    ///
    /// # Errors
    /// Keeps the ordinary typed signature/plan/lease/record refusal on foreign
    /// purpose, reentry or exact-grant rejection. This grants no Guest issue.
    pub fn admit_host_prepare_argument_once_v5(
        &mut self,
        authority: &BrokerAuthority,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        self.admit_host_exact_once_v5(authority, artifacts, request, current_clock,
            prior_fence, BrokerVerb::HostPrepareExecutionArgumentV2)
    }

    fn admit_host_exact_once_v5(
        &mut self,
        authority: &BrokerAuthority,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
        selected_verb: BrokerVerb,
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.entered {
            self.closed.get_or_insert(BrokerAdmissionError::RequestMismatch);
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.entered = true;
        if authority.domain != BrokerDomain::Host || request.verb != selected_verb {
            self.result = Some(Err(BrokerAdmissionError::RequestMismatch));
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let outcome = authority.admit_with_plan_rotation_retaining_v4(
            artifacts, request, current_clock, Some(prior_fence),
            AdmissionPhase::ExactGrantRotation, Some(self),
        );
        self.result = Some(outcome.as_ref().map(|_| ()).map_err(|cause| *cause));
        outcome
    }

    /// Borrows the original typed refusal ahead of its coarse public marker.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    fn retain_v4(&mut self, source: SourceErrorV4) {
        if self.source.is_none() { self.source = Some(source); }
    }

    pub(super) fn retain_canonical_v4(&mut self, cause: aos_sandbox_core::CanonicalCborError) {
        self.retain_v4(SourceErrorV4::Canonical(cause));
    }

    pub(super) fn retain_plan_v4(&mut self, cause: aos_sandbox_core::BrokerPlanVerificationError) {
        self.retain_v4(SourceErrorV4::Plan(cause));
    }

    pub(super) fn retain_lease_v4(&mut self, cause: aos_sandbox_core::OwnershipLeaseVerificationError) {
        self.retain_v4(SourceErrorV4::Lease(cause));
    }

    pub(super) fn retain_record_v4(&mut self, cause: AuthorizationRecordError) {
        self.retain_v4(SourceErrorV4::Record(cause));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn original_typed_decoder_cause_precedes_later_projection_or_reentry() {
        let mut original = BrokerSignedAdmissionOriginalV4::default();
        let cause = decode_signature(&[], artifact_limits(MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES)).unwrap_err();
        original.retain_canonical_v4(cause);
        original.result = Some(Err(BrokerAdmissionError::VerificationFailed));
        original.retain_lease_v4(aos_sandbox_core::OwnershipLeaseVerificationError::AuthorityExpired);
        original.closed = Some(BrokerAdmissionError::RequestMismatch);

        let error = original.failure().unwrap();
        let cause = error.source().unwrap().downcast_ref::<aos_sandbox_core::CanonicalCborError>().unwrap();
        assert!(matches!(cause, aos_sandbox_core::CanonicalCborError::Truncated { offset: 0 }));
        assert!(original.failure().unwrap().source().unwrap()
            .downcast_ref::<aos_sandbox_core::OwnershipLeaseVerificationError>().is_none());
    }
}
