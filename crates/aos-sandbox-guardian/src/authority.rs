//! Signed Guardian-plan and ownership-lease admission.

use aos_sandbox_core::format::{
    CanonicalCborError, DecodeLimits, decode_broker_authorization_plan, decode_signature,
};
use aos_sandbox_core::{
    BrokerAudience, BrokerGrantTarget, BrokerPlanExpectation, BrokerPlanRequest,
    BrokerPlanTrustAnchor, BrokerPlanVerificationError, BrokerVerb, GuardianPlanBinding,
    IncarnationId, LeaseFenceOutcome, NodeId, ObjectDigest, OwnershipLeaseExpectation,
    OwnershipLeaseTrustAnchor, OwnershipLeaseVerificationError, ProtocolId, ProtocolVersion,
    RawClockProvenance, RawPairedClockSample, prepare_local_lease_record, verify_broker_plan,
    verify_ownership_lease,
};

use crate::{DurablyPersistedGuardian, GuardianState, GuardianStateCodecError};

const MAXIMUM_PLAN_BYTES: usize = 256 * 1024;
const MAXIMUM_LEASE_BYTES: usize = 64 * 1024;
const MAXIMUM_SIGNATURE_BYTES: usize = 64 * 1024;
const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// Borrows the exact four portable authority artifacts supplied at startup.
#[derive(Clone, Copy, Debug)]
pub struct GuardianArtifacts<'a> {
    /// Canonical controller-signed Guardian broker plan bytes.
    pub broker_plan: &'a [u8],
    /// Canonical detached signature over `broker_plan`.
    pub broker_plan_signature: &'a [u8],
    /// Canonical ownership-authority lease bytes.
    pub ownership_lease: &'a [u8],
    /// Canonical detached signature over `ownership_lease`.
    pub ownership_lease_signature: &'a [u8],
}

/// Owns the protected trust roots and node identity for guardian admission.
pub struct GuardianAuthority {
    plan_anchor: BrokerPlanTrustAnchor,
    lease_anchor: OwnershipLeaseTrustAnchor,
    node: NodeId,
    clock_provenance: RawClockProvenance,
}

impl GuardianAuthority {
    /// Constructs a guardian verifier from protected local configuration.
    ///
    /// # Errors
    ///
    /// Returns [`GuardianAuthorityError::InvalidConfiguration`] for a sentinel
    /// node identity.
    pub fn new(
        plan_anchor: BrokerPlanTrustAnchor,
        lease_anchor: OwnershipLeaseTrustAnchor,
        node: NodeId,
        clock_provenance: RawClockProvenance,
    ) -> Result<Self, GuardianAuthorityError> {
        if node.as_bytes() == &[0; 16] {
            return Err(GuardianAuthorityError::InvalidConfiguration);
        }
        Ok(Self {
            plan_anchor,
            lease_anchor,
            node,
            clock_provenance,
        })
    }

    /// Verifies and intersects one exact signed plan/lease pair.
    ///
    /// A prior record from another boot is never authority and is replaced only
    /// after the current boot's independently signed plan binding and current
    /// lease both verify. Same-boot state enforces monotonic lease and desired
    /// generations; equal-generation plan equivocation fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`GuardianAuthorityError`] for malformed or mismatched artifacts,
    /// wrong incarnation/node/boot/provenance, stale/equivocal state, expired
    /// authority, or deadline arithmetic failure.
    pub fn admit(
        &self,
        artifacts: GuardianArtifacts<'_>,
        expected_incarnation: [u8; 16],
        current_clock: &RawPairedClockSample,
        prior: Option<&GuardianState>,
    ) -> Result<PendingGuardianState, GuardianAuthorityError> {
        if expected_incarnation == [0; 16] || current_clock.provenance() != self.clock_provenance {
            return Err(GuardianAuthorityError::InvalidConfiguration);
        }

        // Decoding supplies an untrusted expectation only. Signature checking
        // below is what turns the exact bytes into controller authority.
        let decoded_plan =
            decode_broker_authorization_plan(artifacts.broker_plan, limits(MAXIMUM_PLAN_BYTES))?;
        if decoded_plan.assignment().incarnation()
            != IncarnationId::from_bytes(expected_incarnation)
        {
            return Err(GuardianAuthorityError::IncarnationMismatch);
        }
        let plan_signature = decode_signature(
            artifacts.broker_plan_signature,
            limits(MAXIMUM_SIGNATURE_BYTES),
        )
        .map_err(GuardianAuthorityError::CanonicalSignature)?;
        let verified_plan = verify_broker_plan(
            artifacts.broker_plan,
            &plan_signature,
            &self.plan_anchor,
            BrokerPlanExpectation {
                audience: BrokerAudience::Guardian,
                protocol: ProtocolId::Guardian,
                protocol_version: ProtocolVersion::new(1, 0),
                assignment: decoded_plan.assignment(),
                node: self.node,
                now_seconds: current_clock.wall_seconds(),
            },
            limits(MAXIMUM_PLAN_BYTES),
        )?;
        if verified_plan.plan().grants().len() != 1 {
            return Err(GuardianAuthorityError::PlanNotNarrow);
        }

        let lease_signature = decode_signature(
            artifacts.ownership_lease_signature,
            limits(MAXIMUM_SIGNATURE_BYTES),
        )
        .map_err(GuardianAuthorityError::CanonicalSignature)?;
        let verified_lease = verify_ownership_lease(
            artifacts.ownership_lease,
            &lease_signature,
            &self.lease_anchor,
            OwnershipLeaseExpectation {
                assignment: verified_plan.plan().assignment(),
                node: self.node,
                ownership_authority: verified_plan.plan().ownership_authority(),
                clock: current_clock,
            },
            limits(MAXIMUM_LEASE_BYTES),
        )?;
        let binding = GuardianPlanBinding::new(
            verified_plan.plan().assignment(),
            self.node,
            current_clock.host_boot_id(),
            verified_lease.lease().lease_generation(),
            verified_lease.lease_digest(),
        )
        .map_err(|_| GuardianAuthorityError::InvalidPlanBinding)?;
        verified_plan.match_request(BrokerPlanRequest {
            verb: BrokerVerb::GuardianArm,
            target: BrokerGrantTarget::Assignment,
            argument_commitment: binding.commitment(),
            request_bytes: binding.encoded_len(),
            descriptor_count: 0,
        })?;

        validate_high_water(prior, &verified_plan, &verified_lease)?;
        let same_boot_prior =
            prior.filter(|state| state.host_boot_id() == &current_clock.host_boot_id());
        validate_same_boot_plan(same_boot_prior, &verified_plan, &verified_lease)?;
        let pending_lease = prepare_local_lease_record(
            same_boot_prior.map(GuardianState::local_lease),
            &verified_lease,
            current_clock,
        )?;
        let plan_deadline = plan_deadline(
            verified_plan.plan().expires_seconds(),
            current_clock.wall_seconds(),
            current_clock.boottime_nanoseconds(),
        )?;
        let mut effective_deadline =
            plan_deadline.min(pending_lease.record.fail_stop_boottime_nanoseconds());
        if let Some(prior) = same_boot_prior
            && pending_lease.outcome == LeaseFenceOutcome::Replay
        {
            effective_deadline = effective_deadline.min(prior.deadline_boottime_nanoseconds());
        }
        if effective_deadline <= current_clock.boottime_nanoseconds() {
            return Err(GuardianAuthorityError::DeadlineExpired);
        }
        let state = GuardianState::new(
            verified_plan.plan_digest(),
            verified_plan.plan().assignment().desired_generation(),
            verified_plan.plan().expires_seconds(),
            effective_deadline,
            pending_lease.record,
        )?;
        Ok(PendingGuardianState {
            state,
            predecessor_digest: prior.map(GuardianState::record_digest),
        })
    }

    /// Rechecks the same exact artifacts after durable state readback.
    ///
    /// No readiness token is returned if persistence consumed the remaining
    /// authority, the wall/BOOTTIME pair changed incompatibly, or re-admission
    /// produces any byte other than the exact durable state.
    ///
    /// # Errors
    ///
    /// Returns [`GuardianAuthorityError`] for every admission error or durable
    /// state mismatch.
    pub fn confirm_current(
        &self,
        artifacts: GuardianArtifacts<'_>,
        expected_incarnation: [u8; 16],
        current_clock: &RawPairedClockSample,
        durable: DurablyPersistedGuardian,
    ) -> Result<ReadinessConfirmedGuardian, GuardianAuthorityError> {
        let confirmed = self.admit(
            artifacts,
            expected_incarnation,
            current_clock,
            Some(durable.state()),
        )?;
        if confirmed.state != *durable.state() {
            return Err(GuardianAuthorityError::DurableStateMismatch);
        }
        Ok(ReadinessConfirmedGuardian {
            state: durable.state,
        })
    }
}

/// Proves that signed authority remained live after durable exact readback.
#[derive(Debug)]
pub struct ReadinessConfirmedGuardian {
    state: GuardianState,
}

impl ReadinessConfirmedGuardian {
    /// Returns the exact durably committed and freshly reverified state.
    #[must_use]
    pub const fn state(&self) -> &GuardianState {
        &self.state
    }

    /// Returns the exclusive effective `CLOCK_BOOTTIME` deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.state.deadline_boottime_nanoseconds()
    }
}

/// Carries verified authority that is not usable until durable commit.
#[derive(Debug)]
pub struct PendingGuardianState {
    pub(crate) state: GuardianState,
    pub(crate) predecessor_digest: Option<ObjectDigest>,
}

impl PendingGuardianState {
    /// Returns the pending state for diagnostics and persistence tests.
    #[must_use]
    pub const fn state(&self) -> &GuardianState {
        &self.state
    }

    /// Consumes pending authority as non-ready state.
    ///
    /// This is useful to compare prospective state during reconciliation. It
    /// cannot construct [`ReadinessConfirmedGuardian`].
    #[must_use]
    pub fn into_state(self) -> GuardianState {
        self.state
    }
}

/// Reports guardian authority admission or post-persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum GuardianAuthorityError {
    /// Protected node, incarnation, or clock provenance is invalid.
    #[error("invalid guardian authority configuration")]
    InvalidConfiguration,
    /// The signed plan names another guardian incarnation.
    #[error("guardian plan incarnation mismatch")]
    IncarnationMismatch,
    /// Canonical broker-plan decoding failed.
    #[error("guardian broker plan is malformed: {0}")]
    CanonicalPlan(#[from] CanonicalCborError),
    /// Canonical signature decoding failed.
    #[error("guardian signature is malformed: {0}")]
    CanonicalSignature(CanonicalCborError),
    /// Controller plan verification failed.
    #[error("guardian broker plan verification failed: {0}")]
    Plan(#[from] BrokerPlanVerificationError),
    /// Ownership-lease verification or local fencing failed.
    #[error("guardian ownership lease verification failed: {0}")]
    Lease(#[from] OwnershipLeaseVerificationError),
    /// Guardian plans must carry exactly one arm grant.
    #[error("guardian broker plan is not a single-operation plan")]
    PlanNotNarrow,
    /// The boot/lease plan commitment contains a sentinel.
    #[error("guardian plan binding is invalid")]
    InvalidPlanBinding,
    /// Desired-state generation moved backwards, including across reboot.
    #[error("guardian desired generation is stale")]
    StaleDesiredGeneration,
    /// Ownership-lease generation moved backwards, including across reboot.
    #[error("guardian ownership lease generation is stale")]
    StaleLeaseGeneration,
    /// A renewal changed the assignment or owning node across restart.
    #[error("guardian assignment changed across lease renewal")]
    AssignmentChanged,
    /// Equal lease generations carried different signed lease bytes.
    #[error("guardian equal-generation ownership lease equivocation")]
    LeaseEquivocation,
    /// Equal-generation authority changed its signed plan.
    #[error("guardian equal-generation plan equivocation")]
    PlanEquivocation,
    /// Plan deadline conversion overflowed or had no remaining time.
    #[error("guardian plan deadline is invalid")]
    InvalidPlanDeadline,
    /// The effective BOOTTIME deadline has elapsed.
    #[error("guardian authority deadline has elapsed")]
    DeadlineExpired,
    /// State codec rejected the candidate.
    #[error("guardian state is invalid: {0}")]
    State(#[from] GuardianStateCodecError),
    /// Fresh re-admission differed from exact durable readback.
    #[error("guardian durable state changed during readiness confirmation")]
    DurableStateMismatch,
}

fn validate_high_water(
    prior: Option<&GuardianState>,
    plan: &aos_sandbox_core::VerifiedBrokerPlan,
    lease: &aos_sandbox_core::VerifiedOwnershipLease,
) -> Result<(), GuardianAuthorityError> {
    let Some(prior) = prior else {
        return Ok(());
    };
    let desired_generation = plan.plan().assignment().desired_generation();
    if desired_generation < prior.desired_generation() {
        return Err(GuardianAuthorityError::StaleDesiredGeneration);
    }
    if lease.lease().lease_generation() < prior.lease_generation() {
        return Err(GuardianAuthorityError::StaleLeaseGeneration);
    }
    if lease.lease().assignment() != prior.local_lease().assignment()
        || lease.lease().node() != prior.local_lease().node()
    {
        return Err(GuardianAuthorityError::AssignmentChanged);
    }
    if lease.lease().lease_generation() == prior.lease_generation()
        && lease.lease_digest() != prior.local_lease().lease_digest()
    {
        return Err(GuardianAuthorityError::LeaseEquivocation);
    }
    Ok(())
}

fn validate_same_boot_plan(
    prior: Option<&GuardianState>,
    plan: &aos_sandbox_core::VerifiedBrokerPlan,
    lease: &aos_sandbox_core::VerifiedOwnershipLease,
) -> Result<(), GuardianAuthorityError> {
    let Some(prior) = prior else {
        return Ok(());
    };
    if lease.lease().lease_generation() == prior.lease_generation()
        && plan.plan_digest() != prior.plan_digest()
    {
        return Err(GuardianAuthorityError::PlanEquivocation);
    }
    Ok(())
}

fn plan_deadline(
    plan_expires_seconds: i64,
    wall_seconds: i64,
    boottime_nanoseconds: u64,
) -> Result<u64, GuardianAuthorityError> {
    // The adapter pairs BOOTTIME sampled before a whole-second REALTIME value.
    // Reserving one complete wall tick covers truncation; intervening sampling
    // delay then makes this deadline earlier, never later, than wall expiry.
    let remaining = plan_expires_seconds
        .checked_sub(wall_seconds)
        .and_then(|value| value.checked_sub(1))
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(GuardianAuthorityError::InvalidPlanDeadline)?;
    remaining
        .checked_mul(NANOSECONDS_PER_SECOND)
        .and_then(|value| boottime_nanoseconds.checked_add(value))
        .ok_or(GuardianAuthorityError::InvalidPlanDeadline)
}

fn limits(maximum_bytes: usize) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes,
        ..DecodeLimits::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_deadline_reserves_the_truncated_wall_tick() {
        let deadline = plan_deadline(105, 100, 7)
            .unwrap_or_else(|error| panic!("test deadline failed: {error}"));

        assert_eq!(deadline, 4_000_000_007);
        assert!(plan_deadline(101, 100, 7).is_err());
    }
}
