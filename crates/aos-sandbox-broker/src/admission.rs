//! Common signed-plan and ownership-lease admission.
//!
//! Audience crates supply exact canonical semantics. This module alone turns
//! those semantics plus protected trust and time into authenticated pending
//! records. Returned records are not executable authority until durably
//! committed and checked again through [`BrokerAuthority::check_before_effect`].

use aos_sandbox::journal::RecordNamespace;
use aos_sandbox_core::format::decode_signature;
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerAssignment, BrokerAudience, BrokerGrantTarget,
    BrokerPlanExpectation, BrokerPlanRequest, BrokerPlanTrustAnchor, BrokerVerb,
    CLOCK_PAIR_TOLERANCE_NANOSECONDS, DecodeLimits, NodeId, ObjectDigest,
    OwnershipLeaseExpectation, OwnershipLeaseTrustAnchor, ProtocolId, ProtocolVersion,
    RawPairedClockSample, intersect_broker_admission, negotiate_protocol,
    prepare_local_lease_record, verify_broker_plan, verify_ownership_lease,
};
use aos_sandbox_protocol::session::{
    MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES, MAXIMUM_BROKER_PLAN_BYTES,
    MAXIMUM_OWNERSHIP_LEASE_BYTES, ValidatedUntrustedAuthorizationArtifacts,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::record::{
    BrokerAuthorizationFenceV1, BrokerDomain, BrokerEffectIntentV1, BrokerLocalRecordDomain,
    NodeJournalMacKey, open_authorization_fence, open_effect_intent, open_local_record,
    seal_authorization_fence, seal_effect_intent, seal_local_record,
};

/// Reports a closed failure before broker effect authority can be consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BrokerAdmissionError {
    /// Protected local authority configuration is invalid.
    #[error("invalid broker authority configuration")]
    InvalidConfiguration,
    /// Signed plan or ownership-lease verification failed.
    #[error("broker authority artifacts failed verification")]
    VerificationFailed,
    /// Request semantics, bounds, or assignment do not match signed authority.
    #[error("request is outside signed broker authority")]
    RequestMismatch,
    /// Authenticated durable state is malformed, stale, equivocal, or misplaced.
    #[error("broker authorization fence rejected admission")]
    FenceRejected,
}

/// Classifies whether an authenticated effect may still cross its first
/// physical-effect boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerEffectClockDispositionV1 {
    /// The authenticated effect remains inside its exclusive deadline.
    Fresh,
    /// The authenticated effect has reached or passed its exclusive deadline.
    Expired,
}

/// Supplies exact audience-owned facts to common authority admission.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionRequest<'a> {
    /// Receiving broker audience.
    pub audience: BrokerAudience,
    /// Independently versioned local broker protocol.
    pub protocol: ProtocolId,
    /// Exact negotiated protocol version.
    pub protocol_version: ProtocolVersion,
    /// Assignment carried by the validated request.
    pub assignment: BrokerAssignment,
    /// Exact nonzero request identifier.
    pub request_id: [u8; 16],
    /// Exact received method-specific protobuf body.
    pub request_body: &'a [u8],
    /// Exact count of already-validated ancillary descriptor roles.
    pub descriptor_count: u16,
    /// Audience-specific canonical semantic verb.
    pub verb: BrokerVerb,
    /// Audience-specific canonical resource target.
    pub target: BrokerGrantTarget,
    /// Commitment to audience-specific request and catalog semantics.
    pub argument_commitment: BrokerArgumentCommitment,
    /// Exclusive request-local BOOTTIME effect deadline.
    pub request_deadline_boottime_nanoseconds: u64,
}

/// Owns protected trust, node identity, and journal authentication state.
pub struct BrokerAuthority {
    domain: BrokerDomain,
    plan_anchor: BrokerPlanTrustAnchor,
    lease_anchor: OwnershipLeaseTrustAnchor,
    node: NodeId,
    journal_mac_key: NodeJournalMacKey,
}

impl BrokerAuthority {
    /// Constructs authority from already validated protected anchors.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::InvalidConfiguration`] for sentinel
    /// node or journal-key values.
    pub fn new(
        domain: BrokerDomain,
        plan_anchor: BrokerPlanTrustAnchor,
        lease_anchor: OwnershipLeaseTrustAnchor,
        node: NodeId,
        journal_key_id: [u8; 16],
        journal_secret: [u8; 32],
    ) -> Result<Self, BrokerAdmissionError> {
        let journal_secret = Zeroizing::new(journal_secret);
        if node.as_bytes() == &[0; 16] {
            return Err(BrokerAdmissionError::InvalidConfiguration);
        }
        let journal_mac_key = NodeJournalMacKey::new(domain, journal_key_id, *journal_secret)
            .map_err(|_| BrokerAdmissionError::InvalidConfiguration)?;
        Ok(Self {
            domain,
            plan_anchor,
            lease_anchor,
            node,
            journal_mac_key,
        })
    }

    /// Verifies and intersects one exact request with protected local state.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError`] for any signature, context, semantic,
    /// bound, clock, lease, prior-fence, or durable-state mismatch.
    pub fn admit(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        self.admit_with_plan_rotation(artifacts, request, current_clock, prior_fence, false)
    }

    /// Admits an exact Host execution grant while retaining the prior lease.
    ///
    /// The caller must keep the prior base-plan fence as its shared lease head;
    /// the returned exact-grant plan is only an effect-specific authorization.
    ///
    /// # Errors
    ///
    /// Rejects a non-execution verb, invalid signature, assignment, lease,
    /// semantic grant, or stale prior fence.
    pub fn admit_host_execution(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: &[u8],
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if self.domain != BrokerDomain::Host
            || !matches!(
                request.verb,
                BrokerVerb::HostApplyExecution | BrokerVerb::HostQueryExecution
            )
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.admit_with_plan_rotation(artifacts, request, current_clock, Some(prior_fence), true)
    }

    fn admit_with_plan_rotation(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: AdmissionRequest<'_>,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
        allow_exact_plan_rotation: bool,
    ) -> Result<VerifiedBrokerAdmission, BrokerAdmissionError> {
        if !supports_signed_admission(request.protocol, request.protocol_version)
            || request.audience.protocol() != request.protocol
            || request.audience != self.domain.audience()
            || request.request_id == [0; 16]
            || request.request_body.is_empty()
            || request.request_deadline_boottime_nanoseconds <= current_clock.boottime_nanoseconds()
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let plan_signature = decode_signature(
            artifacts.broker_plan_signature(),
            artifact_limits(MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES),
        )
        .map_err(|_| BrokerAdmissionError::VerificationFailed)?;
        let verified_plan = verify_broker_plan(
            artifacts.broker_plan(),
            &plan_signature,
            &self.plan_anchor,
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
        .map_err(|_| BrokerAdmissionError::VerificationFailed)?;
        let request_bytes = u32::try_from(request.request_body.len())
            .map_err(|_| BrokerAdmissionError::RequestMismatch)?;
        let matched = verified_plan
            .match_request(BrokerPlanRequest {
                verb: request.verb,
                target: request.target,
                argument_commitment: request.argument_commitment,
                request_bytes,
                descriptor_count: request.descriptor_count,
            })
            .map_err(|_| BrokerAdmissionError::RequestMismatch)?;

        let lease_signature = decode_signature(
            artifacts.ownership_lease_signature(),
            artifact_limits(MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES),
        )
        .map_err(|_| BrokerAdmissionError::VerificationFailed)?;
        let verified_lease = verify_ownership_lease(
            artifacts.ownership_lease(),
            &lease_signature,
            &self.lease_anchor,
            OwnershipLeaseExpectation {
                assignment: request.assignment,
                node: self.node,
                ownership_authority: verified_plan.plan().ownership_authority(),
                clock: current_clock,
            },
            artifact_limits(MAXIMUM_OWNERSHIP_LEASE_BYTES),
        )
        .map_err(|_| BrokerAdmissionError::VerificationFailed)?;

        let sandbox = request.assignment.sandbox();
        let sandbox_key = sandbox.as_bytes();
        let prior = prior_fence
            .map(|bytes| {
                open_authorization_fence(
                    &self.journal_mac_key,
                    RecordNamespace::DesiredState,
                    sandbox_key,
                    bytes,
                )
            })
            .transpose()
            .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        let prior_local = validate_prior_fence(
            prior.as_ref(),
            &verified_plan,
            request.assignment,
            self.node,
            allow_exact_plan_rotation,
        )?;
        let pending_lease = prepare_local_lease_record(prior_local, &verified_lease, current_clock)
            .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        let intersection = intersect_broker_admission(
            matched,
            &verified_lease,
            &pending_lease.record,
            current_clock,
            request.request_id,
            request.argument_commitment.digest(),
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        let fence = BrokerAuthorizationFenceV1::new(
            request.assignment,
            self.node,
            verified_plan.plan_digest(),
            verified_plan.plan().expires_seconds(),
            verified_plan.plan().ownership_authority().clone(),
            pending_lease.record.clone(),
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        let effect_deadline =
            conservative_plan_deadline(verified_plan.plan().expires_seconds(), current_clock)?
                .min(pending_lease.record.fail_stop_boottime_nanoseconds())
                .min(request.request_deadline_boottime_nanoseconds);
        if effect_deadline <= current_clock.boottime_nanoseconds() {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        let effect = BrokerEffectIntentV1::pending(
            &intersection,
            ObjectDigest::from_bytes(Sha256::digest(request.request_body).into()),
            pending_lease.record,
            *current_clock,
            request.request_deadline_boottime_nanoseconds,
            effect_deadline,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        Ok(VerifiedBrokerAdmission { fence, effect })
    }

    /// Authenticates and opens one exact effect-record location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for invalid state.
    pub fn open_effect(
        &self,
        request_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerEffectIntentV1, BrokerAdmissionError> {
        open_effect_intent(
            &self.journal_mac_key,
            RecordNamespace::Effect,
            request_id,
            bytes,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Authenticates and opens one exact assignment-fence record location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for malformed,
    /// unauthenticated, or relocated state.
    pub fn open_fence(
        &self,
        sandbox_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, BrokerAdmissionError> {
        open_authorization_fence(
            &self.journal_mac_key,
            RecordNamespace::DesiredState,
            sandbox_id,
            bytes,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Authenticates an assignment fence retained with one exact operation.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for a zero operation
    /// identity or malformed, unauthenticated, or relocated state.
    pub fn open_operation_fence(
        &self,
        operation_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, BrokerAdmissionError> {
        if operation_id == &[0; 16] {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        open_authorization_fence(
            &self.journal_mac_key,
            RecordNamespace::AuthorityPublication,
            operation_id,
            bytes,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Reads a fresh clock and validates it immediately before an effect.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] when the clock source
    /// fails or any signed/local expiry, boot, provenance, or drift bound fails.
    pub fn check_before_effect<F>(
        &self,
        effect: &BrokerEffectIntentV1,
        trusted_clock: &mut F,
    ) -> Result<(), BrokerAdmissionError>
    where
        F: FnMut() -> Result<RawPairedClockSample, BrokerAdmissionError>,
    {
        let current_clock = trusted_clock()?;
        self.validate_effect_clock(effect, &current_clock)
    }

    /// Checks that a durable fence still belongs to current protected identity.
    ///
    /// The journal MAC key must be rotated whenever the protected broker-plan
    /// trust anchor changes because the V1 fence retains the accepted plan
    /// digest but not its signing-key identity. Ownership-authority and node
    /// changes are rejected directly here even if an operator incorrectly
    /// reuses the journal key.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] when the fence names a
    /// different configured node or ownership-authority generation.
    pub fn check_current_fence(
        &self,
        fence: &BrokerAuthorizationFenceV1,
    ) -> Result<(), BrokerAdmissionError> {
        if fence.node() != self.node || fence.ownership_authority() != self.lease_anchor.authority()
        {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        Ok(())
    }

    /// Validates a freshly sampled protected clock against a durable effect.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for expiry, reboot,
    /// provenance substitution, backwards time, or excessive paired-clock drift.
    pub fn validate_effect_clock(
        &self,
        effect: &BrokerEffectIntentV1,
        current_clock: &RawPairedClockSample,
    ) -> Result<(), BrokerAdmissionError> {
        match self.classify_effect_clock(effect, current_clock)? {
            BrokerEffectClockDispositionV1::Fresh => Ok(()),
            BrokerEffectClockDispositionV1::Expired => Err(BrokerAdmissionError::FenceRejected),
        }
    }

    /// Classifies one protected clock sample against an authenticated effect.
    ///
    /// This method distinguishes expiry only after authenticating the complete
    /// paired-clock continuity contract. Callers may use [`Self::validate_effect_clock`]
    /// when they do not need to distinguish an expired effect from another
    /// fail-closed clock rejection.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for reboot, provenance
    /// substitution, backwards time, or excessive paired-clock drift.
    pub fn classify_effect_clock(
        &self,
        effect: &BrokerEffectIntentV1,
        current_clock: &RawPairedClockSample,
    ) -> Result<BrokerEffectClockDispositionV1, BrokerAdmissionError> {
        let wall_elapsed = current_clock
            .wall_seconds()
            .checked_sub(effect.admitted_wall_seconds())
            .and_then(|seconds| u64::try_from(seconds).ok())
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or(BrokerAdmissionError::FenceRejected)?;
        let boottime_elapsed = current_clock
            .boottime_nanoseconds()
            .checked_sub(effect.admitted_boottime_nanoseconds())
            .ok_or(BrokerAdmissionError::FenceRejected)?;
        if current_clock.provenance().as_bytes() != *effect.clock_provenance()
            || wall_elapsed.abs_diff(boottime_elapsed) > CLOCK_PAIR_TOLERANCE_NANOSECONDS
            || current_clock.host_boot_id() != *effect.host_boot_id()
        {
            return Err(BrokerAdmissionError::FenceRejected);
        }

        if current_clock.boottime_nanoseconds() >= effect.effect_deadline_boottime_nanoseconds() {
            Ok(BrokerEffectClockDispositionV1::Expired)
        } else if current_clock.wall_seconds() >= effect.plan_expires_seconds()
            || current_clock.wall_seconds() >= effect.authority_expires_seconds()
        {
            // The BOOTTIME deadline is derived conservatively from both wall
            // expiries. Reaching either wall expiry first indicates clock
            // inconsistency, not a safe tombstone condition.
            Err(BrokerAdmissionError::FenceRejected)
        } else {
            Ok(BrokerEffectClockDispositionV1::Fresh)
        }
    }

    /// Authenticates one assignment fence for its exact durable location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for invalid state.
    pub fn seal_fence(
        &self,
        sandbox_id: &[u8; 16],
        fence: &BrokerAuthorizationFenceV1,
    ) -> Result<Vec<u8>, BrokerAdmissionError> {
        if fence.assignment().sandbox().as_bytes() != sandbox_id {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        seal_authorization_fence(
            &self.journal_mac_key,
            RecordNamespace::DesiredState,
            sandbox_id,
            fence,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Authenticates an assignment fence for one exact operation location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for a zero operation
    /// identity or invalid state.
    pub fn seal_operation_fence(
        &self,
        operation_id: &[u8; 16],
        fence: &BrokerAuthorizationFenceV1,
    ) -> Result<Vec<u8>, BrokerAdmissionError> {
        if operation_id == &[0; 16] {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        seal_authorization_fence(
            &self.journal_mac_key,
            RecordNamespace::AuthorityPublication,
            operation_id,
            fence,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Authenticates one effect for its exact durable location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for invalid state.
    pub fn seal_effect(
        &self,
        request_id: &[u8; 16],
        effect: &BrokerEffectIntentV1,
    ) -> Result<Vec<u8>, BrokerAdmissionError> {
        if effect.request_id() != request_id {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        seal_effect_intent(
            &self.journal_mac_key,
            RecordNamespace::Effect,
            request_id,
            effect,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Authenticates an audience-specific local record at one exact journal location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for invalid bounds or key state.
    pub fn seal_local_record(
        &self,
        namespace: RecordNamespace,
        journal_key: &[u8],
        domain: BrokerLocalRecordDomain,
        payload: &[u8],
    ) -> Result<Vec<u8>, BrokerAdmissionError> {
        seal_local_record(
            &self.journal_mac_key,
            namespace,
            journal_key,
            domain,
            payload,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)
    }

    /// Authenticates an audience-specific record before returning its payload.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for tampering, relocation,
    /// a wrong application domain, or malformed framing.
    pub fn open_local_record<'a>(
        &self,
        namespace: RecordNamespace,
        journal_key: &[u8],
        domain: BrokerLocalRecordDomain,
        bytes: &'a [u8],
    ) -> Result<&'a [u8], BrokerAdmissionError> {
        open_local_record(&self.journal_mac_key, namespace, journal_key, domain, bytes)
            .map_err(|_| BrokerAdmissionError::FenceRejected)
    }
}

fn supports_signed_admission(protocol: ProtocolId, version: ProtocolVersion) -> bool {
    negotiate_protocol(protocol, version).is_ok()
        && (version.minor() >= 1
            || matches!(
                protocol,
                ProtocolId::HostBroker
                    | ProtocolId::MountBroker
                    | ProtocolId::StorageBroker
                    | ProtocolId::NetworkBroker
            ))
}

/// Carries exact authenticated records that callers must commit atomically.
#[derive(Debug)]
pub struct VerifiedBrokerAdmission {
    /// Monotonic assignment/plan/lease fence.
    pub fence: BrokerAuthorizationFenceV1,
    /// Pending non-authorizing effect intent.
    pub effect: BrokerEffectIntentV1,
}

const fn artifact_limits(maximum_bytes: usize) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes,
        maximum_collection_items: 2_048,
        maximum_total_items: 65_536,
        maximum_byte_string_bytes: maximum_bytes,
        maximum_text_bytes: 64 * 1024,
        maximum_depth: 128,
    }
}

fn conservative_plan_deadline(
    plan_expires_seconds: i64,
    clock: &RawPairedClockSample,
) -> Result<u64, BrokerAdmissionError> {
    let remaining_whole_seconds = plan_expires_seconds
        .checked_sub(clock.wall_seconds())
        .and_then(|seconds| seconds.checked_sub(1))
        .and_then(|seconds| u64::try_from(seconds).ok())
        .filter(|seconds| *seconds > 0)
        .ok_or(BrokerAdmissionError::FenceRejected)?;
    let duration = remaining_whole_seconds
        .checked_mul(1_000_000_000)
        .ok_or(BrokerAdmissionError::FenceRejected)?;
    clock
        .boottime_nanoseconds()
        .checked_add(duration)
        .ok_or(BrokerAdmissionError::FenceRejected)
}

fn validate_prior_fence<'a>(
    prior: Option<&'a BrokerAuthorizationFenceV1>,
    plan: &aos_sandbox_core::VerifiedBrokerPlan,
    assignment: BrokerAssignment,
    node: NodeId,
    allow_exact_plan_rotation: bool,
) -> Result<Option<&'a aos_sandbox_core::LocalLeaseRecord>, BrokerAdmissionError> {
    let Some(prior) = prior else {
        return Ok(None);
    };
    let current = prior.assignment();
    if prior.node() != node
        || (assignment.epoch() == current.epoch()
            && plan.plan().ownership_authority() != prior.ownership_authority())
        || assignment.epoch() < current.epoch()
        || (assignment.epoch() == current.epoch()
            && assignment.desired_generation() < current.desired_generation())
        || (assignment.epoch() == current.epoch()
            && assignment.incarnation() != current.incarnation())
        || (assignment.epoch() == current.epoch()
            && assignment.desired_generation() == current.desired_generation()
            && (assignment.digest() != current.digest()
                || (!allow_exact_plan_rotation && plan.plan_digest() != prior.plan_digest())))
    {
        return Err(BrokerAdmissionError::FenceRejected);
    }
    if assignment.epoch() == current.epoch() && assignment.digest() == current.digest() {
        Ok(Some(prior.local_lease_record()))
    } else {
        Ok(None)
    }
}

impl BrokerDomain {
    const fn audience(self) -> BrokerAudience {
        match self {
            Self::Host => BrokerAudience::Host,
            Self::Mount => BrokerAudience::Mount,
            Self::Storage => BrokerAudience::Storage,
            Self::Network => BrokerAudience::Network,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_broker_domains_admit_minor_zero_signed_requests() {
        let cases = [
            (ProtocolId::StorageBroker, ProtocolVersion::new(1, 0)),
            (ProtocolId::HostBroker, ProtocolVersion::new(1, 0)),
            (ProtocolId::MountBroker, ProtocolVersion::new(2, 0)),
            (ProtocolId::NetworkBroker, ProtocolVersion::new(1, 0)),
        ];

        for (protocol, version) in cases {
            assert_eq!(
                supports_signed_admission(protocol, version),
                true,
                "unexpected signed-admission result for {protocol:?}"
            );
        }
    }
}
