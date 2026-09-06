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
    BrokerAuthorizationFenceV1, BrokerDomain, BrokerEffectIntentV2, BrokerLocalRecordDomain,
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
        if request.protocol_version.minor() < 1
            || negotiate_protocol(request.protocol, request.protocol_version).is_err()
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
        let effect = BrokerEffectIntentV2::pending(
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
    ) -> Result<BrokerEffectIntentV2, BrokerAdmissionError> {
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

    /// Reads a fresh clock and validates it immediately before an effect.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] when the clock source
    /// fails or any signed/local expiry, boot, provenance, or drift bound fails.
    pub fn check_before_effect<F>(
        &self,
        effect: &BrokerEffectIntentV2,
        trusted_clock: &mut F,
    ) -> Result<(), BrokerAdmissionError>
    where
        F: FnMut() -> Result<RawPairedClockSample, BrokerAdmissionError>,
    {
        let current_clock = trusted_clock()?;
        self.validate_effect_clock(effect, &current_clock)
    }

    /// Validates a freshly sampled protected clock against a durable effect.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for expiry, reboot,
    /// provenance substitution, backwards time, or excessive paired-clock drift.
    pub fn validate_effect_clock(
        &self,
        effect: &BrokerEffectIntentV2,
        current_clock: &RawPairedClockSample,
    ) -> Result<(), BrokerAdmissionError> {
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
            || current_clock.wall_seconds() >= effect.plan_expires_seconds()
            || current_clock.wall_seconds() >= effect.authority_expires_seconds()
            || current_clock.host_boot_id() != *effect.host_boot_id()
            || current_clock.boottime_nanoseconds() >= effect.effect_deadline_boottime_nanoseconds()
        {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        Ok(())
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

    /// Authenticates one effect for its exact durable location.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerAdmissionError::FenceRejected`] for invalid state.
    pub fn seal_effect(
        &self,
        request_id: &[u8; 16],
        effect: &BrokerEffectIntentV2,
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

/// Carries exact authenticated records that callers must commit atomically.
#[derive(Debug)]
pub struct VerifiedBrokerAdmission {
    /// Monotonic assignment/plan/lease fence.
    pub fence: BrokerAuthorizationFenceV1,
    /// Pending non-authorizing effect intent.
    pub effect: BrokerEffectIntentV2,
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
                || plan.plan_digest() != prior.plan_digest()))
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
