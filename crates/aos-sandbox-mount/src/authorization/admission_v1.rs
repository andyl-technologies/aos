//! Complete signed-plan and ownership-lease admission for mount effects.
//!
//! This module is the sole transition from structurally valid, explicitly
//! untrusted request artifacts to a durable non-authorizing effect intent. It
//! verifies protected trust anchors, exact request/catalog semantics, the
//! current ownership lease, and prior authenticated local fencing before it
//! constructs an admission record. The record still requires a successful
//! journal commit and an immediate trusted-clock recheck before any syscall.
//!
//! Node-local HMAC protects authenticity and record location, but it does not
//! provide rollback resistance. Deployments that treat storage as adversarial
//! must add a protected monotonic anchor or fail closed after restart.

use aos_proto::aos::sandbox::local::v1::BrokerDescriptorRole;
use aos_sandbox::journal::RecordNamespace;
use aos_sandbox_core::format::decode_signature;
use aos_sandbox_core::{
    BrokerAssignment, BrokerAudience, BrokerPlanExpectation, BrokerPlanRequest,
    BrokerPlanTrustAnchor, CLOCK_PAIR_TOLERANCE_NANOSECONDS, DecodeLimits, DesiredGeneration,
    IncarnationId, NodeId, ObjectDigest, OwnershipLeaseExpectation, OwnershipLeaseTrustAnchor,
    ProtocolId, ProtocolVersion, RawPairedClockSample, SandboxId, intersect_broker_admission,
    prepare_local_lease_record, verify_broker_plan, verify_ownership_lease,
};
use aos_sandbox_protocol::ValidatedMountRequest;
use aos_sandbox_protocol::session::{
    MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES, MAXIMUM_BROKER_PLAN_BYTES,
    MAXIMUM_OWNERSHIP_LEASE_BYTES, ValidatedUntrustedAuthorizationArtifacts,
};
use sha2::{Digest as _, Sha256};

use super::semantics_v1::{MountCatalogCommitmentV1, canonical_mount_semantics_v1};
use crate::state::authorization_v1::{
    MountAuthorizationFenceV1, MountEffectIntentV2, NodeJournalMacKey, open_authorization_fence,
    open_effect_intent, seal_authorization_fence, seal_effect_intent,
};

/// Reports a closed failure before mount effect authority can be consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MountAdmissionError {
    /// Protected local authority configuration is invalid.
    #[error("invalid mount authority configuration")]
    InvalidConfiguration,
    /// Signed plan or ownership-lease verification failed.
    #[error("mount authority artifacts failed verification")]
    VerificationFailed,
    /// Request semantics, bounds, or assignment do not match signed authority.
    #[error("mount request is outside signed authority")]
    RequestMismatch,
    /// Authenticated durable state is malformed, stale, equivocal, or misplaced.
    #[error("mount authorization fence rejected admission")]
    FenceRejected,
}

/// Owns protected local trust and journal-authentication configuration.
pub struct MountAuthorityV1 {
    plan_anchor: BrokerPlanTrustAnchor,
    lease_anchor: OwnershipLeaseTrustAnchor,
    node: NodeId,
    journal_mac_key: NodeJournalMacKey,
}

impl MountAuthorityV1 {
    /// Constructs a mount authority from already validated protected anchors.
    ///
    /// # Errors
    ///
    /// Returns [`MountAdmissionError::InvalidConfiguration`] for a sentinel
    /// node or invalid node-local journal key.
    pub fn new(
        plan_anchor: BrokerPlanTrustAnchor,
        lease_anchor: OwnershipLeaseTrustAnchor,
        node: NodeId,
        journal_key_id: [u8; 16],
        journal_secret: [u8; 32],
    ) -> Result<Self, MountAdmissionError> {
        if node.as_bytes() == &[0; 16] {
            return Err(MountAdmissionError::InvalidConfiguration);
        }
        let journal_mac_key = NodeJournalMacKey::new(journal_key_id, journal_secret)
            .map_err(|_| MountAdmissionError::InvalidConfiguration)?;
        Ok(Self {
            plan_anchor,
            lease_anchor,
            node,
            journal_mac_key,
        })
    }

    /// Verifies and intersects one exact request with protected local state.
    ///
    /// `prior_fence` must be the value read from `DesiredState` at the exact
    /// sandbox-ID key, if present. The method authenticates that location before
    /// decoding it. Success is not executable authority until both returned
    /// records are committed and reauthenticated.
    ///
    /// # Errors
    ///
    /// Returns [`MountAdmissionError`] for any signature, context, semantic,
    /// bound, clock, lease, prior-fence, or canonical-state mismatch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        request: &ValidatedMountRequest,
        request_body: &[u8],
        catalog: Option<MountCatalogCommitmentV1>,
        descriptor_roles: &[BrokerDescriptorRole],
        protocol_version: ProtocolVersion,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedMountAdmissionV1, MountAdmissionError> {
        if protocol_version != ProtocolVersion::new(1, 1) {
            return Err(MountAdmissionError::RequestMismatch);
        }
        let semantics = canonical_mount_semantics_v1(request, catalog, descriptor_roles)
            .map_err(|_| MountAdmissionError::RequestMismatch)?;
        let assignment = request_assignment(request)?;
        let plan_signature = decode_signature(
            artifacts.broker_plan_signature(),
            artifact_limits(MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES),
        )
        .map_err(|_| MountAdmissionError::VerificationFailed)?;
        let verified_plan = verify_broker_plan(
            artifacts.broker_plan(),
            &plan_signature,
            &self.plan_anchor,
            BrokerPlanExpectation {
                audience: BrokerAudience::Mount,
                protocol: ProtocolId::MountBroker,
                protocol_version,
                assignment,
                node: self.node,
                now_seconds: current_clock.wall_seconds(),
            },
            artifact_limits(MAXIMUM_BROKER_PLAN_BYTES),
        )
        .map_err(|_| MountAdmissionError::VerificationFailed)?;
        let request_bytes =
            u32::try_from(request_body.len()).map_err(|_| MountAdmissionError::RequestMismatch)?;
        let descriptors = u16::try_from(descriptor_roles.len())
            .map_err(|_| MountAdmissionError::RequestMismatch)?;
        let matched = verified_plan
            .match_request(BrokerPlanRequest {
                verb: semantics.verb(),
                target: semantics.target(),
                argument_commitment: semantics.commitment(),
                request_bytes,
                descriptor_count: descriptors,
            })
            .map_err(|_| MountAdmissionError::RequestMismatch)?;

        let lease_signature = decode_signature(
            artifacts.ownership_lease_signature(),
            artifact_limits(MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES),
        )
        .map_err(|_| MountAdmissionError::VerificationFailed)?;
        let verified_lease = verify_ownership_lease(
            artifacts.ownership_lease(),
            &lease_signature,
            &self.lease_anchor,
            OwnershipLeaseExpectation {
                assignment,
                node: self.node,
                ownership_authority: verified_plan.plan().ownership_authority(),
                clock: current_clock,
            },
            artifact_limits(MAXIMUM_OWNERSHIP_LEASE_BYTES),
        )
        .map_err(|_| MountAdmissionError::VerificationFailed)?;

        let sandbox_key = request.fence().sandbox_id();
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
            .map_err(|_| MountAdmissionError::FenceRejected)?;
        let prior_local =
            validate_prior_fence(prior.as_ref(), &verified_plan, assignment, self.node)?;
        let pending_lease = prepare_local_lease_record(prior_local, &verified_lease, current_clock)
            .map_err(|_| MountAdmissionError::FenceRejected)?;
        let intersection = intersect_broker_admission(
            matched,
            &verified_lease,
            &pending_lease.record,
            current_clock,
            *request.header().request_id(),
            semantics.commitment().digest(),
        )
        .map_err(|_| MountAdmissionError::FenceRejected)?;
        let fence = MountAuthorizationFenceV1::new(
            assignment,
            self.node,
            verified_plan.plan_digest(),
            verified_plan.plan().expires_seconds(),
            verified_plan.plan().ownership_authority().clone(),
            pending_lease.record.clone(),
        )
        .map_err(|_| MountAdmissionError::FenceRejected)?;
        let plan_deadline =
            conservative_plan_deadline(verified_plan.plan().expires_seconds(), current_clock)?;
        let effect_deadline = plan_deadline
            .min(pending_lease.record.fail_stop_boottime_nanoseconds())
            .min(request.header().deadline_boottime_nanoseconds());
        if effect_deadline <= current_clock.boottime_nanoseconds() {
            return Err(MountAdmissionError::FenceRejected);
        }
        let effect = MountEffectIntentV2::pending(
            &intersection,
            ObjectDigest::from_bytes(Sha256::digest(request_body).into()),
            pending_lease.record,
            *current_clock,
            request.header().deadline_boottime_nanoseconds(),
            effect_deadline,
        )
        .map_err(|_| MountAdmissionError::FenceRejected)?;
        Ok(VerifiedMountAdmissionV1 { fence, effect })
    }

    /// Authenticates and opens one exact effect record location.
    ///
    /// # Errors
    ///
    /// Returns [`MountAdmissionError::FenceRejected`] for any authentication or
    /// payload failure.
    pub(crate) fn open_effect(
        &self,
        request_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<MountEffectIntentV2, MountAdmissionError> {
        open_effect_intent(
            &self.journal_mac_key,
            RecordNamespace::Effect,
            request_id,
            bytes,
        )
        .map_err(|_| MountAdmissionError::FenceRejected)
    }

    /// Rechecks durable effect liveness immediately before a syscall.
    ///
    /// The caller must obtain `current_clock` from its protected platform
    /// adapter after the intent commit. Request-provided time is never valid.
    ///
    /// # Errors
    ///
    /// Returns [`MountAdmissionError::FenceRejected`] after plan or authority
    /// wall expiry, host reboot, or the conservative BOOTTIME deadline.
    pub(crate) fn validate_effect_clock(
        &self,
        effect: &MountEffectIntentV2,
        current_clock: &RawPairedClockSample,
    ) -> Result<(), MountAdmissionError> {
        let wall_elapsed = current_clock
            .wall_seconds()
            .checked_sub(effect.admitted_wall_seconds())
            .and_then(|seconds| u64::try_from(seconds).ok())
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or(MountAdmissionError::FenceRejected)?;
        let boottime_elapsed = current_clock
            .boottime_nanoseconds()
            .checked_sub(effect.admitted_boottime_nanoseconds())
            .ok_or(MountAdmissionError::FenceRejected)?;
        if current_clock.provenance().as_bytes() != *effect.clock_provenance()
            || wall_elapsed.abs_diff(boottime_elapsed) > CLOCK_PAIR_TOLERANCE_NANOSECONDS
            || current_clock.wall_seconds() >= effect.plan_expires_seconds()
            || current_clock.wall_seconds() >= effect.authority_expires_seconds()
            || current_clock.host_boot_id() != *effect.host_boot_id()
            || current_clock.boottime_nanoseconds() >= effect.effect_deadline_boottime_nanoseconds()
        {
            return Err(MountAdmissionError::FenceRejected);
        }
        Ok(())
    }

    /// Authenticates one assignment fence for its exact durable location.
    ///
    /// # Errors
    ///
    /// Returns [`MountAdmissionError::FenceRejected`] for invalid state.
    pub(crate) fn seal_fence(
        &self,
        sandbox_id: &[u8; 16],
        fence: &MountAuthorizationFenceV1,
    ) -> Result<Vec<u8>, MountAdmissionError> {
        seal_authorization_fence(
            &self.journal_mac_key,
            RecordNamespace::DesiredState,
            sandbox_id,
            fence,
        )
        .map_err(|_| MountAdmissionError::FenceRejected)
    }

    /// Authenticates one effect intent for its exact durable location.
    ///
    /// # Errors
    ///
    /// Returns [`MountAdmissionError::FenceRejected`] for invalid state.
    pub(crate) fn seal_effect(
        &self,
        request_id: &[u8; 16],
        effect: &MountEffectIntentV2,
    ) -> Result<Vec<u8>, MountAdmissionError> {
        seal_effect_intent(
            &self.journal_mac_key,
            RecordNamespace::Effect,
            request_id,
            effect,
        )
        .map_err(|_| MountAdmissionError::FenceRejected)
    }
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

/// Carries exact authenticated records that must be committed atomically.
#[derive(Debug)]
pub(crate) struct VerifiedMountAdmissionV1 {
    pub(crate) fence: MountAuthorizationFenceV1,
    pub(crate) effect: MountEffectIntentV2,
}

fn request_assignment(
    request: &ValidatedMountRequest,
) -> Result<BrokerAssignment, MountAdmissionError> {
    BrokerAssignment::new(
        SandboxId::from_bytes(*request.fence().sandbox_id()),
        IncarnationId::from_bytes(*request.fence().incarnation_id()),
        aos_sandbox_core::AssignmentEpoch::new(request.fence().assignment_epoch()),
        DesiredGeneration::new(request.fence().desired_generation()),
        ObjectDigest::from_bytes(*request.fence().assignment_digest()),
    )
    .map_err(|_| MountAdmissionError::RequestMismatch)
}

fn conservative_plan_deadline(
    plan_expires_seconds: i64,
    clock: &RawPairedClockSample,
) -> Result<u64, MountAdmissionError> {
    // Wall time has one-second granularity. Removing the current partial
    // second ensures the local deadline can only expire earlier than the
    // signed exclusive wall-clock expiry.
    let remaining_whole_seconds = plan_expires_seconds
        .checked_sub(clock.wall_seconds())
        .and_then(|seconds| seconds.checked_sub(1))
        .and_then(|seconds| u64::try_from(seconds).ok())
        .filter(|seconds| *seconds > 0)
        .ok_or(MountAdmissionError::FenceRejected)?;
    let duration = remaining_whole_seconds
        .checked_mul(1_000_000_000)
        .ok_or(MountAdmissionError::FenceRejected)?;
    clock
        .boottime_nanoseconds()
        .checked_add(duration)
        .ok_or(MountAdmissionError::FenceRejected)
}

fn validate_prior_fence<'a>(
    prior: Option<&'a MountAuthorizationFenceV1>,
    plan: &aos_sandbox_core::VerifiedBrokerPlan,
    assignment: BrokerAssignment,
    node: NodeId,
) -> Result<Option<&'a aos_sandbox_core::LocalLeaseRecord>, MountAdmissionError> {
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
        return Err(MountAdmissionError::FenceRejected);
    }
    if assignment.epoch() == current.epoch() && assignment.digest() == current.digest() {
        Ok(Some(prior.local_lease_record()))
    } else {
        Ok(None)
    }
}
