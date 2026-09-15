//! Dormant Guardian renewal, containment, and cleanup authority reducer.
//!
//! The reducer freezes immutable admission before exposing a plan, binds the
//! exact Network lease gate, and requires a complete Host, Storage, Mount, and
//! Network managed-state snapshot at every effect and recovery boundary. It
//! performs no systemd, network, storage, mount, timer, or kernel operation.
//! Opaque protected-current and post-effect values are constructed only by the
//! crate-sealed dormant protected owner; no production observer is activated.

use aos_sandbox_core::{LeaseAssignment, NodeId, ObjectDigest};
use sha2::{Digest as _, Sha256};

use super::ReadinessConfirmedGuardian;

mod codec;
mod commitment;
mod effect;
mod protected_store;
pub use protected_store::{
    DormantGuardianProtectedCommitV1, DormantGuardianProtectedOwnerErrorV1,
    DormantGuardianProtectedOwnerV1,
};

use commitment::{
    admission_digest, authority_digest, guardian_outcome_digest, managed_snapshot_digest,
    network_fence_digest, receipt_digest,
};
use effect::{next_effect_step, next_effect_step_from_outcome, validate_guardian_effect_current};

const REDUCER_DOMAIN: &[u8] = b"aos.sandbox.guardian.reducer-snapshot.v1\0";
const MAXIMUM_GUARDIAN_RECEIPTS: usize = 4_096;
const MAXIMUM_COMPACTED_GUARDIAN_RECEIPTS: usize = 16_384;
const MAXIMUM_GUARDIAN_CHECKPOINT_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_RELEASE_TIMER_HANDOFFS: usize = 2;
const PROTECTED_EARLY_FREEZE_MARGIN_NANOSECONDS: u64 = 5_000_000_000;
const TIMER_POLICY_DOMAIN: &[u8] = b"aos.sandbox.guardian.timer-policy.v1\0";
const STEP_EVIDENCE_DOMAIN: &[u8] = b"aos.sandbox.guardian.step-evidence.v1\0";
const RELEASE_DOMAIN: &[u8] = b"aos.sandbox.guardian.plan-release.v1\0";

/// Reports a fail-closed Guardian reducer rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum GuardianReducerError {
    /// A required identity, generation, timer, or digest is unspecified.
    #[error("Guardian reducer input contains a zero sentinel")]
    Unspecified,
    /// The four managed domains are missing, duplicated, or out of order.
    #[error("Guardian managed-state snapshot is not the exact closed set")]
    ManagedStateNotCanonical,
    /// Network state does not match the admitted assignment and lease.
    #[error("Guardian Network fence does not match exact authority")]
    NetworkFenceMismatch,
    /// A transition is incompatible with retained authority or worker state.
    #[error("Guardian reducer transition is invalid")]
    InvalidTransition,
    /// A request identity was reused for another immutable admission.
    #[error("Guardian reducer request equivocation")]
    Equivocation,
    /// Another operation is unresolved and must be recovered first.
    #[error("Guardian reducer already has an unresolved operation")]
    Pending,
    /// Protected current evidence differs or does not prove durable admission.
    #[error("Guardian protected-current evidence mismatched")]
    CurrentnessMismatch,
    /// The exclusive BOOTTIME timer is stale, discontinuous, or expired.
    #[error("Guardian renewal timer is stale or expired")]
    TimerMismatch,
    /// An ambiguous effect lacks two equal complete post-effect observations.
    #[error("Guardian post-effect observation is incomplete or unstable")]
    ObservationMismatch,
    /// Old-worker death was not proved before replacement.
    #[error("Guardian old worker is not proved dead")]
    OldWorkerStillLive,
    /// A terminal cleanup receipt forbids resurrection.
    #[error("Guardian assignment cleanup is terminal")]
    Terminal,
    /// The operation sequence or receipt bound is exhausted.
    #[error("Guardian reducer bounded history is exhausted")]
    Exhausted,
    /// An invalid protected observation poisoned the in-memory reducer.
    #[error("Guardian reducer is poisoned")]
    Poisoned,
}

/// Captures exact signed and durable Guardian authority at one admission edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuardianAuthoritySnapshotV1 {
    assignment: LeaseAssignment,
    node: NodeId,
    desired_generation: u64,
    plan_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    host_boot_id: [u8; 16],
    clock_provenance: [u8; 16],
    fail_stop_boottime_nanoseconds: u64,
    durable_state_digest: ObjectDigest,
    digest: ObjectDigest,
}

impl GuardianAuthoritySnapshotV1 {
    /// Derives an exact authority snapshot from freshly confirmed durable state.
    pub(crate) fn from_confirmed(confirmed: &ReadinessConfirmedGuardian) -> Self {
        let state = confirmed.state();
        let lease = state.local_lease();
        let mut value = Self {
            assignment: lease.assignment(),
            node: lease.node(),
            desired_generation: state.desired_generation().get(),
            plan_digest: state.plan_digest(),
            lease_generation: lease.lease_generation(),
            lease_digest: lease.lease_digest(),
            host_boot_id: *lease.host_boot_id(),
            clock_provenance: *lease.clock_provenance(),
            fail_stop_boottime_nanoseconds: state.deadline_boottime_nanoseconds(),
            durable_state_digest: state.record_digest(),
            digest: zero_digest(),
        };
        value.digest = authority_digest(value);
        value
    }

    /// Returns immutable lease assignment semantics.
    pub(crate) const fn assignment(self) -> LeaseAssignment {
        self.assignment
    }

    /// Returns the exact admitted node.
    pub(crate) const fn node(self) -> NodeId {
        self.node
    }

    /// Returns the accepted desired-state generation.
    pub(crate) const fn desired_generation(self) -> u64 {
        self.desired_generation
    }

    /// Returns the accepted ownership-lease generation.
    pub(crate) const fn lease_generation(self) -> u64 {
        self.lease_generation
    }

    /// Returns the accepted ownership-lease digest.
    pub(crate) const fn lease_digest(self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the current host boot identity.
    pub(crate) const fn host_boot_id(self) -> [u8; 16] {
        self.host_boot_id
    }

    /// Returns the exclusive local fail-stop deadline.
    pub(crate) const fn fail_stop_boottime_nanoseconds(self) -> u64 {
        self.fail_stop_boottime_nanoseconds
    }

    /// Returns the canonical authority commitment.
    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Binds Guardian containment to one exact Network namespace and lease gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuardianNetworkFenceV1 {
    assignment: LeaseAssignment,
    network_handle: [u8; 32],
    kernel_boot_id: [u8; 16],
    namespace_device: u64,
    namespace_inode: u64,
    network_kernel_identity_digest: ObjectDigest,
    kernel_plan_digest: ObjectDigest,
    packet_policy_digest: ObjectDigest,
    tc_gate_binding_digest: ObjectDigest,
    network_resource_digest: ObjectDigest,
    network_catalog_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    fail_stop_boottime_nanoseconds: u64,
    session_digest: ObjectDigest,
    currentness_digest: ObjectDigest,
    digest: ObjectDigest,
}

impl GuardianNetworkFenceV1 {
    /// Constructs one exact Network fence without granting Network effects.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        assignment: LeaseAssignment,
        network_handle: [u8; 32],
        kernel_boot_id: [u8; 16],
        namespace_device: u64,
        namespace_inode: u64,
        network_kernel_identity_digest: ObjectDigest,
        kernel_plan_digest: ObjectDigest,
        packet_policy_digest: ObjectDigest,
        tc_gate_binding_digest: ObjectDigest,
        network_resource_digest: ObjectDigest,
        network_catalog_digest: ObjectDigest,
        lease_generation: u64,
        lease_digest: ObjectDigest,
        fail_stop_boottime_nanoseconds: u64,
        session_digest: ObjectDigest,
        currentness_digest: ObjectDigest,
    ) -> Result<Self, GuardianReducerError> {
        let mut value = Self {
            assignment,
            network_handle,
            kernel_boot_id,
            namespace_device,
            namespace_inode,
            network_kernel_identity_digest,
            kernel_plan_digest,
            packet_policy_digest,
            tc_gate_binding_digest,
            network_resource_digest,
            network_catalog_digest,
            lease_generation,
            lease_digest,
            fail_stop_boottime_nanoseconds,
            session_digest,
            currentness_digest,
            digest: zero_digest(),
        };
        if !value.has_complete_identity() {
            return Err(GuardianReducerError::Unspecified);
        }
        value.digest = network_fence_digest(value);
        Ok(value)
    }

    /// Returns the assignment that owns every named Network object.
    pub(crate) const fn assignment(self) -> LeaseAssignment {
        self.assignment
    }

    /// Returns the accepted lease generation.
    pub(crate) const fn lease_generation(self) -> u64 {
        self.lease_generation
    }

    /// Returns the accepted lease digest.
    pub(crate) const fn lease_digest(self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the lease-gate deadline.
    pub(crate) const fn fail_stop_boottime_nanoseconds(self) -> u64 {
        self.fail_stop_boottime_nanoseconds
    }

    /// Returns the exact Network fence commitment.
    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }

    fn has_complete_identity(self) -> bool {
        self.network_handle != [0; 32]
            && self.kernel_boot_id != [0; 16]
            && self.namespace_device != 0
            && self.namespace_inode != 0
            && [
                self.kernel_plan_digest,
                self.network_kernel_identity_digest,
                self.packet_policy_digest,
                self.tc_gate_binding_digest,
                self.network_resource_digest,
                self.network_catalog_digest,
                self.lease_digest,
                self.session_digest,
                self.currentness_digest,
            ]
            .iter()
            .all(|digest| digest.as_bytes() != &[0; 32])
            && self.lease_generation != 0
            && self.fail_stop_boottime_nanoseconds != 0
    }

    fn has_same_kernel_identity(self, prior: Self) -> bool {
        self.assignment == prior.assignment
            && self.network_handle == prior.network_handle
            && self.kernel_boot_id == prior.kernel_boot_id
            && self.namespace_device == prior.namespace_device
            && self.namespace_inode == prior.namespace_inode
            && self.network_kernel_identity_digest == prior.network_kernel_identity_digest
            && self.kernel_plan_digest == prior.kernel_plan_digest
            && self.packet_policy_digest == prior.packet_policy_digest
            && self.tc_gate_binding_digest == prior.tc_gate_binding_digest
    }
}

/// Names the complete fixed set traversed during Guardian containment cleanup.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum GuardianManagedDomainV1 {
    /// Host payload unit, cgroup, and runtime custody.
    Host = 0,
    /// Storage workspace and retained backend custody.
    Storage = 1,
    /// Mount attachment and source custody.
    Mount = 2,
    /// Network namespace, links, policy, and gate custody.
    Network = 3,
}

/// Names one closed managed-resource observation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum GuardianManagedStatusV1 {
    /// No resource is present under this assignment.
    Absent = 0,
    /// The exact current resource is active.
    Active = 1,
    /// Admission is frozen and the resource is contained.
    Contained = 2,
    /// Cleanup is in progress and its effect may be ambiguous.
    CleanupUnknown = 3,
    /// Exact cleanup observation proves the resource released.
    Released = 4,
}

/// Carries exact protected state for one managed authority domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuardianManagedStateV1 {
    domain: GuardianManagedDomainV1,
    generation: u64,
    resource_digest: ObjectDigest,
    observation_digest: ObjectDigest,
    catalog_digest: ObjectDigest,
    currentness_digest: ObjectDigest,
    status: GuardianManagedStatusV1,
}

impl GuardianManagedStateV1 {
    /// Constructs one non-sentinel exact managed-state observation.
    pub(crate) fn new(
        domain: GuardianManagedDomainV1,
        generation: u64,
        resource_digest: ObjectDigest,
        observation_digest: ObjectDigest,
        catalog_digest: ObjectDigest,
        currentness_digest: ObjectDigest,
        status: GuardianManagedStatusV1,
    ) -> Result<Self, GuardianReducerError> {
        if generation == 0
            || resource_digest.as_bytes() == &[0; 32]
            || observation_digest.as_bytes() == &[0; 32]
            || catalog_digest.as_bytes() == &[0; 32]
            || currentness_digest.as_bytes() == &[0; 32]
        {
            return Err(GuardianReducerError::Unspecified);
        }
        Ok(Self {
            domain,
            generation,
            resource_digest,
            observation_digest,
            catalog_digest,
            currentness_digest,
            status,
        })
    }

    /// Returns the closed managed authority domain.
    pub(crate) const fn domain(self) -> GuardianManagedDomainV1 {
        self.domain
    }

    /// Returns the closed observed state.
    pub(crate) const fn status(self) -> GuardianManagedStatusV1 {
        self.status
    }
}

/// Carries exactly one current observation for every managed authority domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuardianManagedSnapshotV1 {
    assignment: LeaseAssignment,
    entries: [GuardianManagedStateV1; 4],
    observed_boottime_nanoseconds: u64,
    session_digest: ObjectDigest,
    currentness_digest: ObjectDigest,
    digest: ObjectDigest,
}

impl GuardianManagedSnapshotV1 {
    /// Constructs the exact ordered Host, Storage, Mount, Network snapshot.
    pub(crate) fn new(
        assignment: LeaseAssignment,
        entries: [GuardianManagedStateV1; 4],
        observed_boottime_nanoseconds: u64,
        session_digest: ObjectDigest,
        currentness_digest: ObjectDigest,
    ) -> Result<Self, GuardianReducerError> {
        let expected = [
            GuardianManagedDomainV1::Host,
            GuardianManagedDomainV1::Storage,
            GuardianManagedDomainV1::Mount,
            GuardianManagedDomainV1::Network,
        ];
        if entries
            .iter()
            .zip(expected)
            .any(|(entry, domain)| entry.domain() != domain)
        {
            return Err(GuardianReducerError::ManagedStateNotCanonical);
        }
        if observed_boottime_nanoseconds == 0
            || session_digest.as_bytes() == &[0; 32]
            || currentness_digest.as_bytes() == &[0; 32]
            || entries
                .iter()
                .any(|entry| entry.currentness_digest != currentness_digest)
        {
            return Err(GuardianReducerError::Unspecified);
        }
        let digest = managed_snapshot_digest(
            assignment,
            entries,
            observed_boottime_nanoseconds,
            session_digest,
            currentness_digest,
        );
        Ok(Self {
            assignment,
            entries,
            observed_boottime_nanoseconds,
            session_digest,
            currentness_digest,
            digest,
        })
    }

    /// Returns the complete fixed ordered state set.
    pub(crate) const fn entries(self) -> [GuardianManagedStateV1; 4] {
        self.entries
    }

    /// Returns the protected observation BOOTTIME.
    pub(crate) const fn observed_boottime_nanoseconds(self) -> u64 {
        self.observed_boottime_nanoseconds
    }

    /// Returns the canonical complete-snapshot commitment.
    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }

    fn all_released(self) -> bool {
        self.entries.iter().all(|entry| {
            matches!(
                entry.status(),
                GuardianManagedStatusV1::Absent | GuardianManagedStatusV1::Released
            )
        })
    }

    fn has_cleanup_unknown(self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.status() == GuardianManagedStatusV1::CleanupUnknown)
    }

    fn allows_active_runtime(self) -> bool {
        !self.has_cleanup_unknown()
            && self.entries[0].status() == GuardianManagedStatusV1::Active
            && matches!(
                self.entries[1].status(),
                GuardianManagedStatusV1::Absent | GuardianManagedStatusV1::Active
            )
            && matches!(
                self.entries[2].status(),
                GuardianManagedStatusV1::Absent | GuardianManagedStatusV1::Active
            )
            && self.entries[3].status() == GuardianManagedStatusV1::Active
    }

    fn allows_contained_runtime(self) -> bool {
        !self.has_cleanup_unknown()
            && matches!(
                self.entries[0].status(),
                GuardianManagedStatusV1::Absent
                    | GuardianManagedStatusV1::Contained
                    | GuardianManagedStatusV1::Released
            )
            && matches!(
                self.entries[3].status(),
                GuardianManagedStatusV1::Absent
                    | GuardianManagedStatusV1::Contained
                    | GuardianManagedStatusV1::Released
            )
    }

    fn allows_early_frozen_runtime(self) -> bool {
        !self.has_cleanup_unknown()
            && self.entries[0].status() == GuardianManagedStatusV1::Contained
            && matches!(
                self.entries[1].status(),
                GuardianManagedStatusV1::Absent | GuardianManagedStatusV1::Active
            )
            && matches!(
                self.entries[2].status(),
                GuardianManagedStatusV1::Absent | GuardianManagedStatusV1::Active
            )
            && self.entries[3].status() == GuardianManagedStatusV1::Active
    }

    fn allows_resume_source(self) -> bool {
        !self.has_cleanup_unknown()
            && self.entries[0].status() == GuardianManagedStatusV1::Contained
            && matches!(
                self.entries[1].status(),
                GuardianManagedStatusV1::Absent | GuardianManagedStatusV1::Active
            )
            && matches!(
                self.entries[2].status(),
                GuardianManagedStatusV1::Absent | GuardianManagedStatusV1::Active
            )
            && matches!(
                self.entries[3].status(),
                GuardianManagedStatusV1::Active | GuardianManagedStatusV1::Contained
            )
    }

    fn does_not_regress_from(self, prior: Self) -> bool {
        self.assignment == prior.assignment
            && self.observed_boottime_nanoseconds >= prior.observed_boottime_nanoseconds
            && self
                .entries
                .iter()
                .zip(prior.entries)
                .all(|(current, previous)| {
                    current.domain == previous.domain && current.generation >= previous.generation
                })
    }

    fn refreshes_same_managed_state(self, prior: Self) -> bool {
        self.assignment == prior.assignment
            && self.observed_boottime_nanoseconds >= prior.observed_boottime_nanoseconds
            && self
                .entries
                .iter()
                .zip(prior.entries)
                .all(|(current, previous)| {
                    current.domain == previous.domain
                        && current.generation == previous.generation
                        && current.resource_digest == previous.resource_digest
                        && current.catalog_digest == previous.catalog_digest
                        && current.currentness_digest == previous.currentness_digest
                        && current.status == previous.status
                })
    }

    fn rebinds_same_managed_state(self, prior: Self, network: GuardianNetworkFenceV1) -> bool {
        self.assignment == prior.assignment
            && self.observed_boottime_nanoseconds >= prior.observed_boottime_nanoseconds
            && self.currentness_digest == network.currentness_digest
            && self
                .entries
                .iter()
                .zip(prior.entries)
                .all(|(current, previous)| {
                    current.domain == previous.domain
                        && current.generation == previous.generation
                        && current.resource_digest == previous.resource_digest
                        && current.catalog_digest == previous.catalog_digest
                        && current.currentness_digest == network.currentness_digest
                        && current.status == previous.status
                })
    }

    fn matches_network_resource(self, network: GuardianNetworkFenceV1) -> bool {
        let entry = self.entries[3];
        (entry.resource_digest == network.network_resource_digest
            || matches!(
                entry.status,
                GuardianManagedStatusV1::Absent | GuardianManagedStatusV1::Released
            ))
            && entry.catalog_digest == network.network_catalog_digest
            && entry.currentness_digest == network.currentness_digest
    }

    fn matches_admitted_network_resource(self, network: GuardianNetworkFenceV1) -> bool {
        let entry = self.entries[3];
        entry.resource_digest == network.network_resource_digest
            && entry.catalog_digest == network.network_catalog_digest
            && entry.currentness_digest == network.currentness_digest
    }
}

/// Carries a protected fixed early-freeze policy commitment.
///
/// No public or crate-visible constructor is supplied. The eventual protected
/// policy adapter must mint this value from the installed Guardian policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedGuardianTimerPolicyV1 {
    early_freeze_margin_nanoseconds: u64,
    digest: ObjectDigest,
}

impl ProtectedGuardianTimerPolicyV1 {
    /// Mints the single installed fixed-margin policy inside the protected owner.
    fn installed() -> Self {
        Self {
            early_freeze_margin_nanoseconds: PROTECTED_EARLY_FREEZE_MARGIN_NANOSECONDS,
            digest: timer_policy_digest(PROTECTED_EARLY_FREEZE_MARGIN_NANOSECONDS),
        }
    }

    fn valid(self) -> bool {
        self.early_freeze_margin_nanoseconds == PROTECTED_EARLY_FREEZE_MARGIN_NANOSECONDS
            && self.digest == timer_policy_digest(self.early_freeze_margin_nanoseconds)
    }
}

/// Models the early-freeze and hard-stop BOOTTIME thresholds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuardianRenewalTimerV1 {
    host_boot_id: [u8; 16],
    clock_provenance: [u8; 16],
    armed_boottime_nanoseconds: u64,
    early_freeze_boottime_nanoseconds: u64,
    hard_stop_boottime_nanoseconds: u64,
    policy_digest: ObjectDigest,
}

impl GuardianRenewalTimerV1 {
    /// Constructs exact exclusive BOOTTIME thresholds for one admitted lease.
    pub(crate) fn new(
        authority: GuardianAuthoritySnapshotV1,
        armed_boottime_nanoseconds: u64,
        policy: ProtectedGuardianTimerPolicyV1,
    ) -> Result<Self, GuardianReducerError> {
        if !policy.valid() {
            return Err(GuardianReducerError::TimerMismatch);
        }
        let hard_stop = authority.fail_stop_boottime_nanoseconds();
        let early_freeze = hard_stop
            .checked_sub(policy.early_freeze_margin_nanoseconds)
            .ok_or(GuardianReducerError::TimerMismatch)?;
        if armed_boottime_nanoseconds == 0
            || armed_boottime_nanoseconds >= early_freeze
            || early_freeze >= hard_stop
        {
            return Err(GuardianReducerError::TimerMismatch);
        }
        Ok(Self {
            host_boot_id: authority.host_boot_id,
            clock_provenance: authority.clock_provenance,
            armed_boottime_nanoseconds,
            early_freeze_boottime_nanoseconds: early_freeze,
            hard_stop_boottime_nanoseconds: hard_stop,
            policy_digest: policy.digest,
        })
    }

    /// Returns the exclusive early-freeze threshold.
    pub(crate) const fn early_freeze_boottime_nanoseconds(self) -> u64 {
        self.early_freeze_boottime_nanoseconds
    }

    /// Returns the exclusive hard-stop threshold.
    pub(crate) const fn hard_stop_boottime_nanoseconds(self) -> u64 {
        self.hard_stop_boottime_nanoseconds
    }

    fn valid_for(self, authority: GuardianAuthoritySnapshotV1) -> bool {
        self.host_boot_id == authority.host_boot_id
            && self.clock_provenance == authority.clock_provenance
            && self.hard_stop_boottime_nanoseconds == authority.fail_stop_boottime_nanoseconds()
            && self.policy_digest == timer_policy_digest(PROTECTED_EARLY_FREEZE_MARGIN_NANOSECONDS)
            && self
                .hard_stop_boottime_nanoseconds
                .checked_sub(PROTECTED_EARLY_FREEZE_MARGIN_NANOSECONDS)
                == Some(self.early_freeze_boottime_nanoseconds)
            && self.armed_boottime_nanoseconds != 0
            && self.armed_boottime_nanoseconds < self.early_freeze_boottime_nanoseconds
    }
}

/// Names one closed Guardian authority or recovery operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum GuardianReducerActionV1 {
    /// Arms a first worker and matching Network gate.
    Arm = 0,
    /// Advances the lease gate and Guardian timer under newer authority.
    Renew = 1,
    /// Requests the best-effort payload freeze at the early BOOTTIME edge.
    EarlyFreeze = 2,
    /// Contains the assignment after explicit revocation.
    Revoke = 3,
    /// Contains the assignment at the authenticated deadline.
    Expire = 4,
    /// Contains the assignment after any enforcement loss.
    EnforcementLoss = 5,
    /// Reissues only after exact old-worker death is proved.
    ReplaceWorker = 6,
    /// Traverses all managed domains and commits exact cleanup.
    Cleanup = 7,
    /// Safely restores Guardian, timer, Network gate, then payload execution.
    Resume = 8,
}

/// Names a protected fail-closed containment cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum GuardianCauseKindV1 {
    /// A protected authority source observed explicit revocation.
    Revocation = 0,
    /// A protected monitor observed loss of mandatory enforcement.
    EnforcementLoss = 1,
}

/// Carries protected cause evidence that request bytes cannot fabricate.
///
/// The crate-sealed dormant fixed owner decodes it only inside a canonical
/// admission carrier; reducer currentness checks remain the authority boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedGuardianCauseEvidenceV1 {
    kind: GuardianCauseKindV1,
    assignment: LeaseAssignment,
    authority_digest: ObjectDigest,
    source_digest: ObjectDigest,
    session_digest: ObjectDigest,
    currentness_digest: ObjectDigest,
    observation_ordinal: u64,
    digest: ObjectDigest,
}

/// Binds one operation to exact authority and current managed state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuardianEffectAdmissionV1 {
    request_id: [u8; 16],
    sequence: u64,
    action: GuardianReducerActionV1,
    authority: GuardianAuthoritySnapshotV1,
    network: GuardianNetworkFenceV1,
    managed: GuardianManagedSnapshotV1,
    timer: GuardianRenewalTimerV1,
    worker_identity_digest: ObjectDigest,
    replacement_worker_digest: Option<ObjectDigest>,
    predecessor_receipt_digest: Option<ObjectDigest>,
    cause_evidence: Option<ProtectedGuardianCauseEvidenceV1>,
    digest: ObjectDigest,
}

impl GuardianEffectAdmissionV1 {
    /// Constructs one immutable admission that must be durable before effects.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        request_id: [u8; 16],
        sequence: u64,
        action: GuardianReducerActionV1,
        authority: GuardianAuthoritySnapshotV1,
        network: GuardianNetworkFenceV1,
        managed: GuardianManagedSnapshotV1,
        timer: GuardianRenewalTimerV1,
        worker_identity_digest: ObjectDigest,
        replacement_worker_digest: Option<ObjectDigest>,
        predecessor_receipt_digest: Option<ObjectDigest>,
        cause_evidence: Option<ProtectedGuardianCauseEvidenceV1>,
    ) -> Result<Self, GuardianReducerError> {
        if request_id == [0; 16]
            || sequence == 0
            || worker_identity_digest.as_bytes() == &[0; 32]
            || replacement_worker_digest.is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || predecessor_receipt_digest.is_some_and(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(GuardianReducerError::Unspecified);
        }
        validate_network_authority(authority, network)?;
        if managed.has_cleanup_unknown()
            || managed.assignment != authority.assignment()
            || managed.session_digest != network.session_digest
            || managed.currentness_digest != network.currentness_digest
            || !managed.matches_admitted_network_resource(network)
        {
            return Err(GuardianReducerError::CurrentnessMismatch);
        }
        if !timer.valid_for(authority) {
            return Err(GuardianReducerError::TimerMismatch);
        }
        if (action == GuardianReducerActionV1::ReplaceWorker) != replacement_worker_digest.is_some()
        {
            return Err(GuardianReducerError::InvalidTransition);
        }
        let managed_shape_valid = match action {
            GuardianReducerActionV1::Renew | GuardianReducerActionV1::EarlyFreeze => {
                managed.allows_active_runtime()
            }
            GuardianReducerActionV1::Arm
            | GuardianReducerActionV1::ReplaceWorker
            | GuardianReducerActionV1::Cleanup => managed.allows_contained_runtime(),
            GuardianReducerActionV1::Resume => managed.allows_resume_source(),
            GuardianReducerActionV1::Revoke
            | GuardianReducerActionV1::Expire
            | GuardianReducerActionV1::EnforcementLoss => true,
        };
        if !managed_shape_valid {
            return Err(GuardianReducerError::ManagedStateNotCanonical);
        }
        let cause_valid = match (action, cause_evidence) {
            (GuardianReducerActionV1::Revoke, Some(value)) => {
                valid_cause(value, GuardianCauseKindV1::Revocation, authority, network)
            }
            (GuardianReducerActionV1::EnforcementLoss, Some(value)) => valid_cause(
                value,
                GuardianCauseKindV1::EnforcementLoss,
                authority,
                network,
            ),
            (GuardianReducerActionV1::Revoke | GuardianReducerActionV1::EnforcementLoss, None) => {
                false
            }
            (_, None) => true,
            (_, Some(_)) => false,
        };
        if !cause_valid
            || (action == GuardianReducerActionV1::Resume) != predecessor_receipt_digest.is_some()
        {
            return Err(GuardianReducerError::InvalidTransition);
        }

        let digest = admission_digest(
            request_id,
            sequence,
            action,
            authority.digest(),
            network.digest(),
            managed.digest(),
            timer,
            worker_identity_digest,
            replacement_worker_digest,
            predecessor_receipt_digest,
            cause_evidence,
        );
        Ok(Self {
            request_id,
            sequence,
            action,
            authority,
            network,
            managed,
            timer,
            worker_identity_digest,
            replacement_worker_digest,
            predecessor_receipt_digest,
            cause_evidence,
            digest,
        })
    }

    /// Returns the idempotency request identity.
    pub(crate) const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the exact operation sequence.
    pub(crate) const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the closed reducer action.
    pub(crate) const fn action(self) -> GuardianReducerActionV1 {
        self.action
    }

    /// Returns the canonical admission commitment.
    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Carries fresh protected evidence required before any effect plan is exposed.
///
/// Construction is crate-sealed in the dormant fixed protected-store owner,
/// which decodes a root-owned canonical carrier and requires the reducer to
/// bind durable admission, managed domains, Network fence, worker, and clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedGuardianCurrentV1 {
    admission_digest: ObjectDigest,
    durable_reducer_digest: ObjectDigest,
    authority_digest: ObjectDigest,
    prior_network_fence_digest: ObjectDigest,
    admitted_network_fence_digest: ObjectDigest,
    managed_snapshot_digest: ObjectDigest,
    managed: GuardianManagedSnapshotV1,
    host_boot_id: [u8; 16],
    clock_provenance: [u8; 16],
    observed_boottime_nanoseconds: u64,
    observation_ordinal: u64,
    worker_identity_digest: ObjectDigest,
    worker_resource_digest: ObjectDigest,
    worker_currentness_digest: ObjectDigest,
    current_worker_live: bool,
    old_worker_dead: bool,
    admitted_worker_absent: bool,
    network_default_drop: bool,
    renewal_timer_current: bool,
    network_lease_gate_current: bool,
    payload_frozen: bool,
    payload_stopped: bool,
    payload_released: bool,
}

/// Names one closed external effect in required order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardianEffectStepV1 {
    /// Arms or atomically renews the exact Network lease gate.
    ProgramNetworkLeaseGate,
    /// Restores default-drop on the exact retained Network objects.
    DefaultDropNetwork,
    /// Requests the narrow Host early-freeze operation.
    RequestPayloadFreeze,
    /// Stops the payload through its exact Host identity.
    StopPayload,
    /// Verifies that the prior Guardian worker is wholly dead.
    VerifyOldWorkerDead,
    /// Starts only the exact replacement Guardian worker.
    StartGuardianWorker,
    /// Releases payload work only after Guardian and fail-stop enforcement.
    ReleasePayload,
    /// Reprograms the absolute BOOTTIME timer.
    ProgramRenewalTimer,
    /// Traverses exact Host managed state.
    TraverseHost,
    /// Traverses exact Storage managed state.
    TraverseStorage,
    /// Traverses exact Mount managed state.
    TraverseMount,
    /// Traverses exact Network managed state.
    TraverseNetwork,
    /// Verifies the complete post-effect state twice.
    VerifyCompleteState,
}

/// Carries a move-only commitment awaiting effect-unknown protected readback.
#[derive(Debug)]
pub(crate) struct GuardianEffectPreflightV1 {
    admission_digest: ObjectDigest,
    step_attempt_digest: ObjectDigest,
    recovery_digest: ObjectDigest,
}

/// Carries a durable exact plan-release watermark awaiting readback.
#[derive(Debug)]
pub(crate) struct GuardianReleasePreflightV1 {
    admission_digest: ObjectDigest,
    step_attempt_digest: ObjectDigest,
    release_digest: ObjectDigest,
    recovery_digest: ObjectDigest,
}

/// Carries a non-clone effect plan after durable admission was reobserved.
#[derive(Debug)]
pub(crate) struct GuardianEffectPlanV1 {
    admission: GuardianEffectAdmissionV1,
    step: GuardianEffectStepV1,
    step_attempt_digest: ObjectDigest,
    recovery_digest: ObjectDigest,
    released_boottime_nanoseconds: u64,
    released_observation_ordinal: u64,
    release_digest: ObjectDigest,
}

impl GuardianEffectPlanV1 {
    /// Returns the exact immutable admission.
    pub(crate) const fn admission(&self) -> GuardianEffectAdmissionV1 {
        self.admission
    }

    /// Returns the sole fresh-observation-selected effect step.
    pub(crate) const fn step(&self) -> GuardianEffectStepV1 {
        self.step
    }

    /// Returns the exact plan-release watermark the outcome must echo.
    pub(crate) const fn release_digest(&self) -> ObjectDigest {
        self.release_digest
    }

    /// Returns the ambiguous recovery commitment made before plan release.
    pub(crate) const fn recovery_digest(&self) -> ObjectDigest {
        self.recovery_digest
    }
}

/// Carries two equal complete protected post-effect snapshots.
///
/// The crate-sealed dormant fixed owner decodes the canonical observation.
/// Request and worker bytes cannot mint cleanup, containment, old-worker-death,
/// or absence proof, and no production observer is activated here.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProtectedGuardianOutcomeV1 {
    admission_digest: ObjectDigest,
    authority_digest: ObjectDigest,
    network_fence_digest: ObjectDigest,
    worker_identity_digest: ObjectDigest,
    worker_resource_digest: ObjectDigest,
    worker_currentness_digest: ObjectDigest,
    managed: GuardianManagedSnapshotV1,
    observation_ordinal: u64,
    effect_evidence_digest: ObjectDigest,
    step_attempt_digest: ObjectDigest,
    release_digest: ObjectDigest,
    predecessor_digest: ObjectDigest,
    first_snapshot_digest: ObjectDigest,
    second_snapshot_digest: ObjectDigest,
    old_worker_dead: bool,
    admitted_worker_live: bool,
    network_default_drop: bool,
    payload_frozen: bool,
    payload_stopped: bool,
    renewal_timer_current: bool,
    network_lease_gate_current: bool,
    payload_released: bool,
    digest: ObjectDigest,
}

/// Reports the only durable nonterminal phases used for crash recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardianReducerPhaseV1 {
    /// Immutable admission is frozen; no plan has been exposed.
    Frozen,
    /// The pending attempt is durable, but no plan-release watermark exists.
    EffectUnknown,
    /// The exact worker plan watermark is durable but unexposed in this process.
    ///
    /// Recovery treats this phase as exposure-ambiguous and permits observation
    /// only; the timer handoff is solely for the live pre-exposure path.
    ReleaseFrozen,
    /// The plan was returned in this process and must only be observed.
    PlanExposed,
    /// Stable absence proves a replacement may be safely reissued.
    ReissueFrozen,
    /// Complete stable outcome is frozen pending receipt commit.
    Observed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardianContainmentOverrideV1 {
    EarlyFreeze,
    Expire,
    EnforcementLoss,
}

/// Carries protected proof that an in-flight admitted worker died.
///
/// Construction is crate-sealed in the dormant fixed protected-store owner;
/// reducer validation binds the exact attempt, death evidence, and complete
/// post-death current state. No production observer is activated here.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProtectedGuardianWorkerDeathSupersessionV1 {
    admission_digest: ObjectDigest,
    superseded_action: GuardianReducerActionV1,
    step: GuardianEffectStepV1,
    attempt_ordinal: u64,
    step_attempt_digest: ObjectDigest,
    predecessor_current: ProtectedGuardianCurrentV1,
    death_evidence_digest: ObjectDigest,
    current: ProtectedGuardianCurrentV1,
    digest: ObjectDigest,
}

#[derive(Clone, Copy, Debug)]
struct GuardianReleaseTimerHandoffV1 {
    source_action: GuardianReducerActionV1,
    target_action: GuardianReducerActionV1,
    step: GuardianEffectStepV1,
    attempt_ordinal: u64,
    step_attempt_digest: ObjectDigest,
    release_digest: ObjectDigest,
    predecessor_current: ProtectedGuardianCurrentV1,
    released_boottime_nanoseconds: u64,
    released_observation_ordinal: u64,
    current: ProtectedGuardianCurrentV1,
    digest: ObjectDigest,
}

#[derive(Clone, Copy, Debug)]
struct PendingGuardianEffectV1 {
    admission: GuardianEffectAdmissionV1,
    phase: GuardianReducerPhaseV1,
    observation_digest: Option<ObjectDigest>,
    observed_managed: Option<GuardianManagedSnapshotV1>,
    released_boottime_nanoseconds: Option<u64>,
    released_observation_ordinal: Option<u64>,
    last_observation_ordinal: Option<u64>,
    effect_evidence_digest: Option<ObjectDigest>,
    step: Option<GuardianEffectStepV1>,
    next_attempt_ordinal: u64,
    active_attempt_ordinal: Option<u64>,
    step_evidence_count: u64,
    step_evidence_anchor: Option<ObjectDigest>,
    prior_step_evidence_anchor: Option<ObjectDigest>,
    predecessor_current: Option<ProtectedGuardianCurrentV1>,
    step_attempt_digest: Option<ObjectDigest>,
    last_outcome: Option<ProtectedGuardianOutcomeV1>,
    last_completed_action: Option<GuardianReducerActionV1>,
    last_completed_step: Option<GuardianEffectStepV1>,
    last_completed_predecessor: Option<ProtectedGuardianCurrentV1>,
    last_completed_attempt_digest: Option<ObjectDigest>,
    last_completed_attempt_ordinal: Option<u64>,
    last_completed_released_boottime_nanoseconds: Option<u64>,
    last_completed_released_observation_ordinal: Option<u64>,
    containment_override: Option<GuardianContainmentOverrideV1>,
    worker_death_supersession: Option<ProtectedGuardianWorkerDeathSupersessionV1>,
    release_timer_handoffs: [Option<GuardianReleaseTimerHandoffV1>; MAXIMUM_RELEASE_TIMER_HANDOFFS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompactedGuardianReceiptV1 {
    request_id: [u8; 16],
    sequence: u64,
    action: GuardianReducerActionV1,
    admission_digest: ObjectDigest,
    receipt_digest: ObjectDigest,
}

/// Stores one stable idempotent Guardian result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuardianEffectReceiptV1 {
    request_id: [u8; 16],
    sequence: u64,
    admitted_action: GuardianReducerActionV1,
    action: GuardianReducerActionV1,
    admission_digest: ObjectDigest,
    authority_digest: ObjectDigest,
    network_fence_digest: ObjectDigest,
    managed_snapshot_digest: ObjectDigest,
    observation_digest: ObjectDigest,
    step_evidence_count: u64,
    step_evidence_anchor: ObjectDigest,
    last_released_boottime_nanoseconds: u64,
    last_released_observation_ordinal: u64,
    last_observation_ordinal: u64,
    worker_death_supersession_digest: Option<ObjectDigest>,
    terminal: bool,
    digest: ObjectDigest,
}

impl GuardianEffectReceiptV1 {
    /// Returns the exact request identity.
    pub(crate) const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the frozen admission commitment.
    pub(crate) const fn admission_digest(self) -> ObjectDigest {
        self.admission_digest
    }

    /// Reports whether exact four-domain cleanup is terminal.
    pub(crate) const fn terminal(self) -> bool {
        self.terminal
    }

    /// Returns the canonical receipt commitment.
    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Reports fresh admission or exact idempotent replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardianBeginOutcomeV1 {
    /// A new immutable operation was frozen.
    Frozen,
    /// The exact unresolved request already exists.
    PendingReplay(GuardianReducerPhaseV1),
    /// The exact request already committed.
    CommittedReplay(GuardianEffectReceiptV1),
    /// The exact request is below the compaction floor.
    CompactedReplay {
        /// Original operation sequence.
        sequence: u64,
        /// Resolved action, including protected containment handoff.
        action: GuardianReducerActionV1,
        /// Original full receipt commitment.
        receipt_digest: ObjectDigest,
    },
}

/// Directs restart without reissuing an ambiguous effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardianRecoveryDispositionV1 {
    /// No operation is unresolved.
    Idle,
    /// Frozen admission requires complete fresh revalidation.
    RevalidateFrozen(ObjectDigest),
    /// An effect may have run; only observation is allowed.
    ObserveOnly(ObjectDigest),
    /// Old-worker death and replacement absence permit protected reissue.
    RevalidateReissue(ObjectDigest),
    /// Stable observation may be committed without another effect.
    CommitObserved(ObjectDigest),
    /// Exact cleanup is terminal and cannot be resurrected.
    Terminal(GuardianEffectReceiptV1),
}

/// Reduces one assignment's Guardian authority and managed cleanup lineage.
#[derive(Debug)]
pub(crate) struct GuardianAuthorityReducerV1 {
    authority: GuardianAuthoritySnapshotV1,
    network: GuardianNetworkFenceV1,
    managed: GuardianManagedSnapshotV1,
    worker_identity_digest: ObjectDigest,
    timer: GuardianRenewalTimerV1,
    highest_sequence: u64,
    receipt_floor_sequence: u64,
    receipt_anchor_digest: Option<ObjectDigest>,
    pending: Option<PendingGuardianEffectV1>,
    compacted_receipt_index: Vec<CompactedGuardianReceiptV1>,
    receipts: Vec<GuardianEffectReceiptV1>,
    terminal: bool,
    poisoned: bool,
}

/// Owns one bounded canonical Guardian snapshot for protected persistence.
#[derive(Clone, Debug)]
pub(crate) struct GuardianRecoverySnapshotV1 {
    authority: GuardianAuthoritySnapshotV1,
    network: GuardianNetworkFenceV1,
    managed: GuardianManagedSnapshotV1,
    worker_identity_digest: ObjectDigest,
    timer: GuardianRenewalTimerV1,
    highest_sequence: u64,
    receipt_floor_sequence: u64,
    receipt_anchor_digest: Option<ObjectDigest>,
    pending: Option<PendingGuardianEffectV1>,
    compacted_receipt_index: Vec<CompactedGuardianReceiptV1>,
    receipts: Vec<GuardianEffectReceiptV1>,
    terminal: bool,
    poisoned: bool,
    digest: ObjectDigest,
}

/// Authorizes one exact protected Guardian receipt-prefix compaction.
///
/// Construction remains reserved for the protected authority integration.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProtectedGuardianCompactionV1 {
    snapshot_digest: ObjectDigest,
    through_sequence: u64,
    anchor_digest: ObjectDigest,
    replay_index_digest: ObjectDigest,
}

/// Owns a bounded checkpoint envelope awaiting protected durable storage.
///
/// This in-memory value is not evidence of persistence. The private protected
/// adapter must durably write and read back `checkpoint` before recovery.
#[derive(Clone, Debug)]
pub(crate) struct GuardianRecoveryStoreV1 {
    checkpoint: Vec<u8>,
}

impl GuardianRecoveryStoreV1 {
    /// Seals one typed snapshot into a canonical bounded checkpoint envelope.
    pub(crate) fn checkpoint(
        snapshot: GuardianRecoverySnapshotV1,
    ) -> Result<Self, GuardianReducerError> {
        GuardianAuthorityReducerV1::recover(snapshot.clone())?;
        let payload = codec::encode_snapshot(&snapshot)?;
        let decoded = codec::decode_snapshot(&payload)?;
        if decoded.digest != snapshot.digest || codec::encode_snapshot(&decoded)? != payload {
            return Err(GuardianReducerError::ObservationMismatch);
        }
        let checkpoint = encode_guardian_checkpoint(&snapshot, &payload)?;
        Ok(Self { checkpoint })
    }

    /// Validates and owns canonical checkpoint bytes read from protected storage.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes exceed bounds, are noncanonical, or do
    /// not reconstruct one internally consistent Guardian snapshot.
    pub(crate) fn from_checkpoint_bytes(checkpoint: Vec<u8>) -> Result<Self, GuardianReducerError> {
        let store = Self { checkpoint };
        store.clone().recover()?;
        Ok(store)
    }

    /// Borrows the exact canonical bytes that a protected adapter must persist.
    pub(crate) fn checkpoint_bytes(&self) -> &[u8] {
        &self.checkpoint
    }

    /// Verifies canonical bytes before returning the typed snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the envelope or payload is noncanonical or its
    /// typed Guardian state fails recovery validation.
    pub(crate) fn recover(self) -> Result<GuardianRecoverySnapshotV1, GuardianReducerError> {
        let payload = guardian_checkpoint_payload(&self.checkpoint)?;
        let snapshot = codec::decode_snapshot(payload)?;
        if decode_guardian_checkpoint_header(&self.checkpoint)?
            != (
                snapshot.receipt_floor_sequence,
                snapshot.receipt_anchor_digest,
                snapshot.digest,
                snapshot.compacted_receipt_index.len() + snapshot.receipts.len(),
            )
            || self.checkpoint != encode_guardian_checkpoint(&snapshot, payload)?
            || codec::encode_snapshot(&snapshot)? != payload
        {
            return Err(GuardianReducerError::ObservationMismatch);
        }
        GuardianAuthorityReducerV1::recover(snapshot.clone())?;
        Ok(snapshot)
    }
}

impl GuardianAuthorityReducerV1 {
    /// Constructs a reducer from exact protected current state.
    pub(crate) fn new(
        authority: GuardianAuthoritySnapshotV1,
        network: GuardianNetworkFenceV1,
        managed: GuardianManagedSnapshotV1,
        worker_identity_digest: ObjectDigest,
        timer: GuardianRenewalTimerV1,
    ) -> Result<Self, GuardianReducerError> {
        validate_network_authority(authority, network)?;
        if !valid_authority_snapshot(authority)
            || worker_identity_digest.as_bytes() == &[0; 32]
            || !timer.valid_for(authority)
            || managed.has_cleanup_unknown()
            || managed.assignment != authority.assignment()
            || managed.session_digest != network.session_digest
            || managed.currentness_digest != network.currentness_digest
            || !managed.matches_network_resource(network)
        {
            return Err(GuardianReducerError::Unspecified);
        }
        Ok(Self {
            authority,
            network,
            managed,
            worker_identity_digest,
            timer,
            highest_sequence: 0,
            receipt_floor_sequence: 0,
            receipt_anchor_digest: None,
            pending: None,
            compacted_receipt_index: Vec::new(),
            receipts: Vec::new(),
            terminal: false,
            poisoned: false,
        })
    }

    /// Recovers exact bounded durable state without creating effect authority.
    pub(crate) fn recover(
        snapshot: GuardianRecoverySnapshotV1,
    ) -> Result<Self, GuardianReducerError> {
        if snapshot.receipts.len() > MAXIMUM_GUARDIAN_RECEIPTS
            || snapshot.compacted_receipt_index.len() > MAXIMUM_COMPACTED_GUARDIAN_RECEIPTS
            || snapshot.compacted_receipt_index.len() as u64 != snapshot.receipt_floor_sequence
            || snapshot.receipt_anchor_digest.is_some_and(|anchor| {
                anchor != guardian_compacted_anchor(&snapshot.compacted_receipt_index, &[])
            })
            || snapshot.terminal && snapshot.pending.is_some()
            || snapshot.poisoned && snapshot.pending.is_none()
            || snapshot.receipt_floor_sequence > snapshot.highest_sequence
            || (snapshot.receipt_floor_sequence == 0) != snapshot.receipt_anchor_digest.is_none()
            || (snapshot.receipts.is_empty()
                && snapshot.highest_sequence != snapshot.receipt_floor_sequence)
            || (snapshot.receipt_floor_sequence != 0 && snapshot.receipts.is_empty())
            || snapshot
                .receipts
                .iter()
                .enumerate()
                .any(|(index, receipt)| {
                    Some(receipt.sequence)
                        != snapshot
                            .receipt_floor_sequence
                            .checked_add(index as u64)
                            .and_then(|value| value.checked_add(1))
                        || receipt.request_id == [0; 16]
                        || [
                            receipt.admission_digest,
                            receipt.authority_digest,
                            receipt.network_fence_digest,
                            receipt.managed_snapshot_digest,
                            receipt.observation_digest,
                            receipt.step_evidence_anchor,
                            receipt.digest,
                        ]
                        .iter()
                        .any(|digest| digest.as_bytes() == &[0; 32])
                        || receipt.step_evidence_count == 0
                        || receipt.last_released_boottime_nanoseconds == 0
                        || receipt.last_released_observation_ordinal == 0
                        || receipt.last_observation_ordinal
                            <= receipt.last_released_observation_ordinal
                        || receipt.digest != receipt_digest(*receipt)
                        || !valid_guardian_receipt_action(*receipt)
                        || receipt.terminal != (receipt.action == GuardianReducerActionV1::Cleanup)
                        || receipt.terminal && index + 1 != snapshot.receipts.len()
                        || snapshot.receipts[..index]
                            .iter()
                            .any(|prior| prior.request_id == receipt.request_id)
                })
            || snapshot
                .compacted_receipt_index
                .iter()
                .enumerate()
                .any(|(index, receipt)| {
                    receipt.sequence != (index as u64) + 1
                        || receipt.request_id == [0; 16]
                        || [receipt.admission_digest, receipt.receipt_digest]
                            .iter()
                            .any(|digest| digest.as_bytes() == &[0; 32])
                        || snapshot.compacted_receipt_index[..index]
                            .iter()
                            .any(|prior| prior.request_id == receipt.request_id)
                })
            || snapshot
                .compacted_receipt_index
                .last()
                .is_some_and(|receipt| receipt.sequence != snapshot.receipt_floor_sequence)
            || snapshot.receipts.iter().any(|receipt| {
                snapshot
                    .compacted_receipt_index
                    .iter()
                    .any(|prior| prior.request_id == receipt.request_id)
            })
        {
            return Err(GuardianReducerError::ObservationMismatch);
        }
        let last_receipt = snapshot.receipts.last().copied();
        if last_receipt.is_some_and(|receipt| {
            receipt.sequence != snapshot.highest_sequence
                || receipt.authority_digest != snapshot.authority.digest()
                || receipt.network_fence_digest != snapshot.network.digest()
                || receipt.managed_snapshot_digest != snapshot.managed.digest()
                || receipt.terminal != snapshot.terminal
        }) || snapshot.terminal && !snapshot.managed.all_released()
        {
            return Err(GuardianReducerError::InvalidTransition);
        }

        let mut reducer = Self::new(
            snapshot.authority,
            snapshot.network,
            snapshot.managed,
            snapshot.worker_identity_digest,
            snapshot.timer,
        )?;
        reducer.highest_sequence = snapshot.highest_sequence;
        reducer.receipt_floor_sequence = snapshot.receipt_floor_sequence;
        reducer.receipt_anchor_digest = snapshot.receipt_anchor_digest;
        reducer.compacted_receipt_index = snapshot.compacted_receipt_index;
        reducer.receipts = snapshot.receipts;
        reducer.terminal = snapshot.terminal;
        reducer.poisoned = snapshot.poisoned;

        if let Some(pending) = snapshot.pending {
            let expected_sequence = reducer
                .highest_sequence
                .checked_add(1)
                .ok_or(GuardianReducerError::Exhausted)?;
            let shape_valid = match pending.phase {
                GuardianReducerPhaseV1::Frozen => {
                    pending.observation_digest.is_none()
                        && pending.observed_managed.is_none()
                        && pending.step.is_none()
                        && pending.predecessor_current.is_none()
                        && pending.step_attempt_digest.is_none()
                        && pending.released_observation_ordinal.is_none()
                        && pending.active_attempt_ordinal.is_none()
                        && pending.last_outcome.is_none()
                        && pending.containment_override.is_none()
                        && pending.worker_death_supersession.is_none()
                        && pending.release_timer_handoffs.iter().all(Option::is_none)
                }
                GuardianReducerPhaseV1::EffectUnknown => {
                    pending.observation_digest.is_none()
                        && pending.step.is_some()
                        && pending.observed_managed.is_some()
                        && pending.predecessor_current.is_some()
                        && pending.step_attempt_digest.is_some()
                        && pending.released_observation_ordinal.is_none()
                        && pending.active_attempt_ordinal.is_some()
                }
                GuardianReducerPhaseV1::ReleaseFrozen => {
                    pending.observation_digest.is_none()
                        && pending.step.is_some()
                        && pending.observed_managed.is_some()
                        && pending.predecessor_current.is_some()
                        && pending.step_attempt_digest.is_some()
                        && pending.released_observation_ordinal.is_some()
                        && pending.active_attempt_ordinal.is_some()
                }
                GuardianReducerPhaseV1::PlanExposed => {
                    pending.observation_digest.is_none()
                        && pending.step.is_some()
                        && pending.observed_managed.is_some()
                        && pending.predecessor_current.is_some()
                        && pending.step_attempt_digest.is_some()
                        && pending.released_observation_ordinal.is_some()
                        && pending.active_attempt_ordinal.is_some()
                }
                GuardianReducerPhaseV1::ReissueFrozen => {
                    pending.observation_digest.is_none()
                        && pending.observed_managed.is_some()
                        && pending.step.is_none()
                        && pending.predecessor_current.is_none()
                        && pending.step_attempt_digest.is_none()
                        && pending.released_observation_ordinal.is_none()
                        && pending.active_attempt_ordinal.is_none()
                        && (pending.last_outcome.is_some()
                            || pending.worker_death_supersession.is_some()
                            || pending.release_timer_handoffs.iter().any(Option::is_some))
                }
                GuardianReducerPhaseV1::Observed => {
                    pending
                        .observation_digest
                        .is_some_and(|digest| digest.as_bytes() != &[0; 32])
                        && pending.observed_managed.is_some()
                        && pending.step.is_some()
                        && pending.predecessor_current.is_some()
                        && pending.step_attempt_digest.is_some()
                        && pending.released_observation_ordinal.is_some()
                        && pending.active_attempt_ordinal.is_some()
                        && pending.last_outcome.is_some()
                }
            };
            if pending.admission.sequence() != expected_sequence
                || reducer
                    .receipts
                    .iter()
                    .any(|receipt| receipt.request_id() == pending.admission.request_id())
                || !shape_valid
                || pending.released_boottime_nanoseconds.is_some()
                    != pending.released_observation_ordinal.is_some()
                || pending.last_observation_ordinal.is_some()
                    != pending.effect_evidence_digest.is_some()
                || pending.phase == GuardianReducerPhaseV1::Observed
                    && pending.last_observation_ordinal.is_none()
                || (pending.step_evidence_count == 0) != pending.step_evidence_anchor.is_none()
                || (pending.step_evidence_count > 1) != pending.prior_step_evidence_anchor.is_some()
                || (pending.step_evidence_count == 0) != pending.last_outcome.is_none()
                || (pending.step_evidence_count == 0) != pending.last_completed_action.is_none()
                || (pending.step_evidence_count == 0) != pending.last_completed_step.is_none()
                || (pending.step_evidence_count == 0)
                    != pending.last_completed_predecessor.is_none()
                || (pending.step_evidence_count == 0)
                    != pending.last_completed_attempt_digest.is_none()
                || (pending.step_evidence_count == 0)
                    != pending.last_completed_attempt_ordinal.is_none()
                || (pending.step_evidence_count == 0)
                    != pending
                        .last_completed_released_boottime_nanoseconds
                        .is_none()
                || (pending.step_evidence_count == 0)
                    != pending
                        .last_completed_released_observation_ordinal
                        .is_none()
                || pending
                    .step_evidence_count
                    .checked_add(1)
                    .and_then(|value| {
                        value.checked_add(u64::from(pending.worker_death_supersession.is_some()))
                    })
                    .and_then(|value| {
                        value.checked_add(
                            pending.release_timer_handoffs.iter().flatten().count() as u64
                        )
                    })
                    != Some(pending.next_attempt_ordinal)
                || pending.active_attempt_ordinal.is_some_and(|ordinal| {
                    ordinal != pending.next_attempt_ordinal
                        && !(pending.phase == GuardianReducerPhaseV1::Observed
                            && ordinal == pending.step_evidence_count)
                })
                || pending.worker_death_supersession.is_some_and(|evidence| {
                    pending.containment_override
                        != Some(GuardianContainmentOverrideV1::EnforcementLoss)
                        || evidence.attempt_ordinal
                            != pending
                                .step_evidence_count
                                .saturating_add(
                                    pending.release_timer_handoffs.iter().flatten().count() as u64,
                                )
                                .saturating_add(1)
                        || evidence.predecessor_current.prior_network_fence_digest
                            != reducer.network.digest()
                        || evidence.current.prior_network_fence_digest != reducer.network.digest()
                        || !valid_superseded_action_source(pending, evidence.superseded_action)
                        || !valid_worker_death_supersession(pending.admission, evidence)
                })
                || pending.last_outcome.is_some_and(|outcome| {
                    outcome.digest != guardian_outcome_digest(&outcome)
                        || pending.phase == GuardianReducerPhaseV1::Observed
                            && pending.observation_digest != Some(outcome.digest)
                        || outcome.admission_digest != pending.admission.digest()
                        || outcome.authority_digest != pending.admission.authority.digest()
                        || outcome.network_fence_digest != pending.admission.network.digest()
                        || Some(outcome.observation_ordinal) != pending.last_observation_ordinal
                        || Some(outcome.effect_evidence_digest) != pending.effect_evidence_digest
                })
                || !valid_release_timer_handoffs(pending, reducer.network.digest())
                || !valid_recovered_guardian_pending(pending, reducer.network.digest())
                || match (
                    pending.step,
                    pending.predecessor_current,
                    pending.step_attempt_digest,
                    pending.active_attempt_ordinal,
                ) {
                    (Some(step), Some(current), Some(attempt), Some(active_ordinal)) => {
                        attempt
                            != guardian_step_attempt_digest(
                                pending.admission.digest(),
                                step,
                                active_ordinal,
                                current,
                            )
                    }
                    (None, None, None, None) => false,
                    _ => true,
                }
            {
                return Err(GuardianReducerError::InvalidTransition);
            }
            validate_admission_transition(&reducer, pending.admission)?;
            reducer.pending = Some(pending);
        }
        if reducer.snapshot_digest() != snapshot.digest {
            return Err(GuardianReducerError::ObservationMismatch);
        }
        Ok(reducer)
    }

    /// Freezes admission before an effect plan can exist.
    pub(crate) fn begin(
        &mut self,
        admission: GuardianEffectAdmissionV1,
    ) -> Result<GuardianBeginOutcomeV1, GuardianReducerError> {
        self.ensure_healthy()?;
        if let Some(receipt) = self
            .receipts
            .iter()
            .copied()
            .find(|receipt| receipt.request_id() == admission.request_id())
        {
            return if receipt.admission_digest() == admission.digest() {
                Ok(GuardianBeginOutcomeV1::CommittedReplay(receipt))
            } else {
                Err(GuardianReducerError::Equivocation)
            };
        }
        if let Some(receipt) = self
            .compacted_receipt_index
            .iter()
            .copied()
            .find(|receipt| receipt.request_id == admission.request_id())
        {
            return if receipt.admission_digest == admission.digest() {
                Ok(GuardianBeginOutcomeV1::CompactedReplay {
                    sequence: receipt.sequence,
                    action: receipt.action,
                    receipt_digest: receipt.receipt_digest,
                })
            } else {
                Err(GuardianReducerError::Equivocation)
            };
        }
        if self.terminal {
            return Err(GuardianReducerError::Terminal);
        }
        if let Some(pending) = self.pending {
            return if pending.admission.request_id() == admission.request_id()
                && pending.admission.digest() == admission.digest()
            {
                Ok(GuardianBeginOutcomeV1::PendingReplay(pending.phase))
            } else if pending.admission.request_id() == admission.request_id() {
                Err(GuardianReducerError::Equivocation)
            } else {
                Err(GuardianReducerError::Pending)
            };
        }
        let next = self
            .highest_sequence
            .checked_add(1)
            .ok_or(GuardianReducerError::Exhausted)?;
        if admission.sequence() != next {
            return Err(GuardianReducerError::InvalidTransition);
        }
        validate_admission_transition(self, admission)?;
        self.pending = Some(PendingGuardianEffectV1 {
            admission,
            phase: GuardianReducerPhaseV1::Frozen,
            observation_digest: None,
            observed_managed: None,
            released_boottime_nanoseconds: None,
            released_observation_ordinal: None,
            last_observation_ordinal: None,
            effect_evidence_digest: None,
            step: None,
            next_attempt_ordinal: 1,
            active_attempt_ordinal: None,
            step_evidence_count: 0,
            step_evidence_anchor: None,
            prior_step_evidence_anchor: None,
            predecessor_current: None,
            step_attempt_digest: None,
            last_outcome: None,
            last_completed_action: None,
            last_completed_step: None,
            last_completed_predecessor: None,
            last_completed_attempt_digest: None,
            last_completed_attempt_ordinal: None,
            last_completed_released_boottime_nanoseconds: None,
            last_completed_released_observation_ordinal: None,
            containment_override: None,
            worker_death_supersession: None,
            release_timer_handoffs: [None; MAXIMUM_RELEASE_TIMER_HANDOFFS],
        });
        Ok(GuardianBeginOutcomeV1::Frozen)
    }

    /// Marks the effect boundary ambiguous after frozen protected readback.
    pub(crate) fn prepare_effect(
        &mut self,
        current: ProtectedGuardianCurrentV1,
    ) -> Result<GuardianEffectPreflightV1, GuardianReducerError> {
        self.ensure_healthy()?;
        let expected_reducer_digest = self.snapshot_digest();
        let pending = self.pending.ok_or(GuardianReducerError::Pending)?;
        if !matches!(
            pending.phase,
            GuardianReducerPhaseV1::Frozen | GuardianReducerPhaseV1::ReissueFrozen
        ) {
            return Err(GuardianReducerError::Pending);
        }
        validate_guardian_effect_current(
            expected_reducer_digest,
            self.network.digest(),
            pending,
            current,
        )?;
        let protected_source = latest_protected_reissue_current(pending);
        let recovery_current_valid = match (pending.last_outcome, protected_source) {
            (Some(outcome), Some(source))
                if source.observation_ordinal > outcome.observation_ordinal =>
            {
                current.observation_ordinal > source.observation_ordinal
                    && same_guardian_residual(source, current)
            }
            (Some(outcome), _) => guardian_current_matches_outcome(current, outcome),
            (None, Some(source)) => {
                current.observation_ordinal > source.observation_ordinal
                    && same_guardian_residual(source, current)
            }
            (None, None) => true,
        };
        if !recovery_current_valid {
            return Err(GuardianReducerError::CurrentnessMismatch);
        }
        let step = next_effect_step(pending_effect_action(pending), current)
            .ok_or(GuardianReducerError::ObservationMismatch)?;

        let admission = pending.admission;
        let pending = self.pending.as_mut().ok_or(GuardianReducerError::Pending)?;
        pending.phase = GuardianReducerPhaseV1::EffectUnknown;
        pending.step = Some(step);
        pending.observed_managed = Some(current.managed);
        pending.predecessor_current = Some(current);
        pending.active_attempt_ordinal = Some(pending.next_attempt_ordinal);
        let attempt_digest = guardian_step_attempt_digest(
            pending.admission.digest(),
            step,
            pending.next_attempt_ordinal,
            current,
        );
        pending.step_attempt_digest = Some(attempt_digest);
        let recovery_digest = self.snapshot_digest();
        Ok(GuardianEffectPreflightV1 {
            admission_digest: admission.digest(),
            step_attempt_digest: attempt_digest,
            recovery_digest,
        })
    }

    /// Releases a plan only after effect-unknown state has protected readback.
    pub(crate) fn freeze_release(
        &mut self,
        preflight: GuardianEffectPreflightV1,
        current: ProtectedGuardianCurrentV1,
    ) -> Result<GuardianReleasePreflightV1, GuardianReducerError> {
        self.ensure_healthy()?;
        let reducer_digest = self.snapshot_digest();
        let pending = self.pending.ok_or(GuardianReducerError::Pending)?;
        if pending.phase != GuardianReducerPhaseV1::EffectUnknown
            || preflight.admission_digest != pending.admission.digest()
            || preflight.recovery_digest != reducer_digest
            || Some(preflight.step_attempt_digest) != pending.step_attempt_digest
        {
            return Err(GuardianReducerError::CurrentnessMismatch);
        }
        validate_guardian_effect_current(reducer_digest, self.network.digest(), pending, current)?;
        let predecessor = pending
            .predecessor_current
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        if current.observation_ordinal <= predecessor.observation_ordinal
            || !same_guardian_residual(predecessor, current)
        {
            return Err(GuardianReducerError::CurrentnessMismatch);
        }
        let pending = self.pending.as_mut().ok_or(GuardianReducerError::Pending)?;
        pending.released_boottime_nanoseconds = Some(current.observed_boottime_nanoseconds);
        pending.released_observation_ordinal = Some(current.observation_ordinal);
        pending.phase = GuardianReducerPhaseV1::ReleaseFrozen;
        let admission = pending.admission;
        let step_attempt_digest = pending
            .step_attempt_digest
            .ok_or(GuardianReducerError::Pending)?;
        let release_digest = guardian_plan_release_digest(admission.digest(), step_attempt_digest);
        let recovery_digest = self.snapshot_digest();

        Ok(GuardianReleasePreflightV1 {
            admission_digest: admission.digest(),
            step_attempt_digest,
            release_digest,
            recovery_digest,
        })
    }

    /// Supersedes an unexposed released plan when its timer window closes.
    ///
    /// This consumes the same move-only release token that would otherwise
    /// expose the plan, so a released plan cannot later take this handoff.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no exact released attempt, the protected
    /// observation does not preserve its residual, the timer has not crossed,
    /// or the bounded handoff history is exhausted.
    pub(crate) fn handoff_release_timer(
        &mut self,
        release: GuardianReleasePreflightV1,
        current: ProtectedGuardianCurrentV1,
    ) -> Result<(), GuardianReducerError> {
        self.ensure_healthy()?;
        let durable_digest = self.snapshot_digest();
        let mut pending = self.pending.ok_or(GuardianReducerError::Pending)?;
        let predecessor = pending
            .predecessor_current
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        let step = pending.step.ok_or(GuardianReducerError::Pending)?;
        let attempt_ordinal = pending
            .active_attempt_ordinal
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        let step_attempt_digest = pending
            .step_attempt_digest
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        let released_boottime_nanoseconds = pending
            .released_boottime_nanoseconds
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        let released_observation_ordinal = pending
            .released_observation_ordinal
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        let source_action = pending_effect_action(pending);
        if pending.phase != GuardianReducerPhaseV1::ReleaseFrozen
            || release.admission_digest != pending.admission.digest()
            || release.step_attempt_digest != step_attempt_digest
            || release.release_digest
                != guardian_plan_release_digest(pending.admission.digest(), step_attempt_digest)
            || release.recovery_digest != durable_digest
            || current.durable_reducer_digest != durable_digest
            || current.observation_ordinal <= released_observation_ordinal
            || !same_guardian_residual(predecessor, current)
            || validate_guardian_effect_current(
                durable_digest,
                self.network.digest(),
                pending,
                current,
            ) != Err(GuardianReducerError::TimerMismatch)
        {
            return Err(GuardianReducerError::CurrentnessMismatch);
        }
        let target_action = if current.observed_boottime_nanoseconds
            >= pending.admission.timer.hard_stop_boottime_nanoseconds()
        {
            GuardianReducerActionV1::Expire
        } else {
            GuardianReducerActionV1::EarlyFreeze
        };
        let slot = pending
            .release_timer_handoffs
            .iter()
            .position(Option::is_none)
            .ok_or(GuardianReducerError::Exhausted)?;
        let mut handoff = GuardianReleaseTimerHandoffV1 {
            source_action,
            target_action,
            step,
            attempt_ordinal,
            step_attempt_digest,
            release_digest: guardian_plan_release_digest(
                pending.admission.digest(),
                step_attempt_digest,
            ),
            predecessor_current: predecessor,
            released_boottime_nanoseconds,
            released_observation_ordinal,
            current,
            digest: zero_digest(),
        };
        handoff.digest = guardian_release_timer_handoff_digest(handoff);
        pending.release_timer_handoffs[slot] = Some(handoff);
        pending.next_attempt_ordinal = pending
            .next_attempt_ordinal
            .checked_add(1)
            .ok_or(GuardianReducerError::Exhausted)?;
        pending.phase = GuardianReducerPhaseV1::ReissueFrozen;
        pending.containment_override = Some(match target_action {
            GuardianReducerActionV1::EarlyFreeze => GuardianContainmentOverrideV1::EarlyFreeze,
            GuardianReducerActionV1::Expire => GuardianContainmentOverrideV1::Expire,
            _ => return Err(GuardianReducerError::InvalidTransition),
        });
        pending.observed_managed = Some(current.managed);
        pending.step = None;
        pending.predecessor_current = None;
        pending.step_attempt_digest = None;
        pending.active_attempt_ordinal = None;
        pending.released_boottime_nanoseconds = None;
        pending.released_observation_ordinal = None;
        self.pending = Some(pending);
        Ok(())
    }

    /// Rolls back an unexposed attempt after fresh protected revalidation.
    pub(crate) fn revalidate_unreleased(
        &mut self,
        current: ProtectedGuardianCurrentV1,
    ) -> Result<(), GuardianReducerError> {
        self.ensure_healthy()?;
        let durable_digest = self.snapshot_digest();
        let mut pending = self.pending.ok_or(GuardianReducerError::Pending)?;
        let predecessor = pending
            .predecessor_current
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        if pending.phase != GuardianReducerPhaseV1::EffectUnknown
            || current.durable_reducer_digest != durable_digest
            || current.observation_ordinal <= predecessor.observation_ordinal
            || !same_guardian_residual(predecessor, current)
        {
            return Err(GuardianReducerError::CurrentnessMismatch);
        }
        validate_guardian_effect_current(durable_digest, self.network.digest(), pending, current)?;
        let reissue = pending.last_outcome.is_some()
            || pending.worker_death_supersession.is_some()
            || pending.containment_override.is_some();
        pending.phase = if reissue {
            GuardianReducerPhaseV1::ReissueFrozen
        } else {
            GuardianReducerPhaseV1::Frozen
        };
        pending.observed_managed = reissue.then_some(current.managed);
        pending.step = None;
        pending.predecessor_current = None;
        pending.step_attempt_digest = None;
        pending.active_attempt_ordinal = None;
        self.pending = Some(pending);
        Ok(())
    }

    /// Supersedes an in-flight attempt after protected admitted-worker death.
    pub(crate) fn supersede_worker_death(
        &mut self,
        evidence: ProtectedGuardianWorkerDeathSupersessionV1,
    ) -> Result<(), GuardianReducerError> {
        self.ensure_healthy()?;
        let durable_digest = self.snapshot_digest();
        let mut pending = self.pending.ok_or(GuardianReducerError::Pending)?;
        let predecessor = pending
            .predecessor_current
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        let attempt_digest = pending
            .step_attempt_digest
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        let step = pending
            .step
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        let attempt_ordinal = pending
            .active_attempt_ordinal
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        let superseded_action = pending_effect_action(pending);
        let current = evidence.current;
        if !matches!(
            pending.phase,
            GuardianReducerPhaseV1::EffectUnknown | GuardianReducerPhaseV1::ReleaseFrozen
        ) || pending.worker_death_supersession.is_some()
            || evidence.admission_digest != pending.admission.digest()
            || evidence.superseded_action != superseded_action
            || evidence.step != step
            || evidence.attempt_ordinal != attempt_ordinal
            || evidence.step_attempt_digest != attempt_digest
            || evidence.predecessor_current != predecessor
            || evidence.death_evidence_digest.as_bytes() == &[0; 32]
            || evidence.digest != guardian_worker_death_supersession_digest(evidence)
            || !valid_worker_death_supersession(pending.admission, evidence)
            || current.durable_reducer_digest != durable_digest
            || current.admission_digest != pending.admission.digest()
            || current.authority_digest != pending.admission.authority.digest()
            || current.admitted_network_fence_digest != pending.admission.network.digest()
            || current.managed_snapshot_digest != current.managed.digest()
            || !current
                .managed
                .refreshes_same_managed_state(predecessor.managed)
            || current.observation_ordinal <= predecessor.observation_ordinal
            || current.worker_identity_digest != predecessor.worker_identity_digest
            || current.worker_resource_digest == predecessor.worker_resource_digest
            || current.worker_currentness_digest == predecessor.worker_currentness_digest
            || current.current_worker_live
            || !current.admitted_worker_absent
            || !current.old_worker_dead
            || current.network_default_drop != predecessor.network_default_drop
            || current.renewal_timer_current != predecessor.renewal_timer_current
            || current.network_lease_gate_current != predecessor.network_lease_gate_current
            || current.payload_frozen != predecessor.payload_frozen
            || current.payload_stopped != predecessor.payload_stopped
            || current.payload_released != predecessor.payload_released
            || next_effect_step(superseded_action, predecessor) != Some(step)
            || next_effect_step(GuardianReducerActionV1::EnforcementLoss, current).is_none()
        {
            return Err(GuardianReducerError::CurrentnessMismatch);
        }

        pending.phase = GuardianReducerPhaseV1::ReissueFrozen;
        pending.containment_override = Some(GuardianContainmentOverrideV1::EnforcementLoss);
        pending.worker_death_supersession = Some(evidence);
        pending.observed_managed = Some(current.managed);
        pending.next_attempt_ordinal = pending
            .next_attempt_ordinal
            .checked_add(1)
            .ok_or(GuardianReducerError::Exhausted)?;
        pending.step = None;
        pending.predecessor_current = None;
        pending.step_attempt_digest = None;
        pending.active_attempt_ordinal = None;
        pending.released_boottime_nanoseconds = None;
        pending.released_observation_ordinal = None;
        self.pending = Some(pending);
        Ok(())
    }

    /// Exposes one plan only after protected readback of its release watermark.
    pub(crate) fn release_effect(
        &mut self,
        release: GuardianReleasePreflightV1,
        current: ProtectedGuardianCurrentV1,
    ) -> Result<GuardianEffectPlanV1, GuardianReducerError> {
        self.ensure_healthy()?;
        let pending = self.pending.ok_or(GuardianReducerError::Pending)?;
        let predecessor = pending
            .predecessor_current
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        let step = pending.step.ok_or(GuardianReducerError::Pending)?;
        let step_attempt_digest = pending
            .step_attempt_digest
            .ok_or(GuardianReducerError::Pending)?;
        let released_ordinal = pending
            .released_observation_ordinal
            .ok_or(GuardianReducerError::CurrentnessMismatch)?;
        if pending.phase != GuardianReducerPhaseV1::ReleaseFrozen
            || release.admission_digest != pending.admission.digest()
            || release.step_attempt_digest != step_attempt_digest
            || release.release_digest
                != guardian_plan_release_digest(pending.admission.digest(), step_attempt_digest)
            || release.recovery_digest != self.snapshot_digest()
            || current.durable_reducer_digest != release.recovery_digest
            || current.observation_ordinal <= released_ordinal
            || !same_guardian_residual(predecessor, current)
        {
            return Err(GuardianReducerError::CurrentnessMismatch);
        }
        validate_guardian_effect_current(
            release.recovery_digest,
            self.network.digest(),
            pending,
            current,
        )?;

        let plan = GuardianEffectPlanV1 {
            admission: pending.admission,
            step,
            step_attempt_digest,
            released_boottime_nanoseconds: pending
                .released_boottime_nanoseconds
                .ok_or(GuardianReducerError::CurrentnessMismatch)?,
            released_observation_ordinal: released_ordinal,
            release_digest: release.release_digest,
            recovery_digest: release.recovery_digest,
        };
        self.pending
            .as_mut()
            .ok_or(GuardianReducerError::Pending)?
            .phase = GuardianReducerPhaseV1::PlanExposed;
        Ok(plan)
    }

    /// Accepts a complete stable protected outcome after an ambiguous effect.
    pub(crate) fn observe(
        &mut self,
        outcome: ProtectedGuardianOutcomeV1,
    ) -> Result<(), GuardianReducerError> {
        self.ensure_healthy()?;
        match self.validate_observation(outcome) {
            Ok(pending) => {
                self.pending = Some(pending);
                Ok(())
            }
            Err(error @ GuardianReducerError::TimerMismatch) => Err(error),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    fn validate_observation(
        &self,
        outcome: ProtectedGuardianOutcomeV1,
    ) -> Result<PendingGuardianEffectV1, GuardianReducerError> {
        let mut pending = self.pending.ok_or(GuardianReducerError::Pending)?;
        let prior_managed = pending
            .observed_managed
            .unwrap_or(pending.admission.managed);
        let predecessor_current = pending
            .predecessor_current
            .ok_or(GuardianReducerError::ObservationMismatch)?;
        if !matches!(
            pending.phase,
            GuardianReducerPhaseV1::ReleaseFrozen | GuardianReducerPhaseV1::PlanExposed
        ) || outcome.admission_digest != pending.admission.digest()
            || outcome.authority_digest != pending.admission.authority.digest()
            || outcome.network_fence_digest != pending.admission.network.digest()
            || !outcome
                .managed
                .matches_network_resource(pending.admission.network)
            || outcome.worker_identity_digest
                != pending
                    .admission
                    .replacement_worker_digest
                    .unwrap_or(pending.admission.worker_identity_digest)
            || outcome.worker_resource_digest.as_bytes() == &[0; 32]
            || outcome.worker_currentness_digest.as_bytes() == &[0; 32]
            || outcome.first_snapshot_digest.as_bytes() == &[0; 32]
            || outcome.first_snapshot_digest != outcome.second_snapshot_digest
            || outcome.predecessor_digest != guardian_current_digest(predecessor_current)
            || outcome.digest != guardian_outcome_digest(&outcome)
            || outcome.managed.session_digest != pending.admission.network.session_digest
            || outcome.managed.currentness_digest != pending.admission.network.currentness_digest
            || !outcome.managed.does_not_regress_from(prior_managed)
            || outcome.observation_ordinal == 0
            || outcome.observation_ordinal <= predecessor_current.observation_ordinal
            || outcome.effect_evidence_digest.as_bytes() == &[0; 32]
            || Some(outcome.step_attempt_digest) != pending.step_attempt_digest
            || outcome.release_digest
                != guardian_plan_release_digest(
                    pending.admission.digest(),
                    pending
                        .step_attempt_digest
                        .ok_or(GuardianReducerError::ObservationMismatch)?,
                )
            || pending
                .released_observation_ordinal
                .is_some_and(|ordinal| outcome.observation_ordinal <= ordinal)
            || pending
                .released_boottime_nanoseconds
                .is_some_and(|released| outcome.managed.observed_boottime_nanoseconds() < released)
            || !valid_managed_action_progress(
                pending_effect_action(pending),
                prior_managed,
                outcome.managed,
            )
            || !valid_guardian_step_progress(
                pending
                    .step
                    .ok_or(GuardianReducerError::ObservationMismatch)?,
                predecessor_current,
                &outcome,
            )
        {
            return Err(GuardianReducerError::ObservationMismatch);
        }
        let observed_time = outcome.managed.observed_boottime_nanoseconds();
        let timer_crossed = match pending_effect_action(pending) {
            GuardianReducerActionV1::Arm
            | GuardianReducerActionV1::Renew
            | GuardianReducerActionV1::ReplaceWorker
            | GuardianReducerActionV1::Resume => {
                observed_time >= pending.admission.timer.early_freeze_boottime_nanoseconds()
            }
            GuardianReducerActionV1::EarlyFreeze => {
                observed_time >= pending.admission.timer.hard_stop_boottime_nanoseconds()
            }
            _ => false,
        };
        if timer_crossed {
            append_guardian_step_evidence(&mut pending, &outcome)?;
            pending.containment_override = Some(
                if observed_time >= pending.admission.timer.hard_stop_boottime_nanoseconds() {
                    GuardianContainmentOverrideV1::Expire
                } else {
                    GuardianContainmentOverrideV1::EarlyFreeze
                },
            );
            pending.phase = GuardianReducerPhaseV1::ReissueFrozen;
            pending.observation_digest = None;
            pending.observed_managed = Some(outcome.managed);
            pending.step = None;
            pending.predecessor_current = None;
            pending.step_attempt_digest = None;
            pending.active_attempt_ordinal = None;
            pending.released_boottime_nanoseconds = None;
            pending.released_observation_ordinal = None;
            pending.last_outcome = Some(outcome);
            return Ok(pending);
        }
        let action = pending_effect_action(pending);
        let valid = guardian_terminal_outcome_valid(action, pending.admission, &outcome);
        if !valid {
            if let Some(_next_step) = next_effect_step_from_outcome(action, &outcome) {
                append_guardian_step_evidence(&mut pending, &outcome)?;
                pending.phase = GuardianReducerPhaseV1::ReissueFrozen;
                pending.observation_digest = None;
                pending.observed_managed = Some(outcome.managed);
                pending.step = None;
                pending.predecessor_current = None;
                pending.step_attempt_digest = None;
                pending.active_attempt_ordinal = None;
                pending.released_boottime_nanoseconds = None;
                pending.released_observation_ordinal = None;
                pending.last_outcome = Some(outcome);
                return Ok(pending);
            }
            return Err(GuardianReducerError::ObservationMismatch);
        }
        append_guardian_step_evidence(&mut pending, &outcome)?;
        pending.phase = GuardianReducerPhaseV1::Observed;
        pending.observation_digest = Some(outcome.digest);
        pending.observed_managed = Some(outcome.managed);
        pending.last_observation_ordinal = Some(outcome.observation_ordinal);
        pending.effect_evidence_digest = Some(outcome.effect_evidence_digest);
        pending.last_outcome = Some(outcome);
        Ok(pending)
    }

    /// Commits exact observation into one stable idempotent receipt.
    pub(crate) fn commit_observed(
        &mut self,
    ) -> Result<GuardianEffectReceiptV1, GuardianReducerError> {
        self.ensure_healthy()?;
        let pending = self.pending.take().ok_or(GuardianReducerError::Pending)?;
        let Some(observation_digest) = pending.observation_digest else {
            self.pending = Some(pending);
            return Err(GuardianReducerError::Pending);
        };
        let Some(managed) = pending.observed_managed else {
            self.pending = Some(pending);
            return Err(GuardianReducerError::Pending);
        };
        if pending.phase != GuardianReducerPhaseV1::Observed
            || managed.digest().as_bytes() == &[0; 32]
        {
            self.pending = Some(pending);
            return Err(GuardianReducerError::ObservationMismatch);
        }
        if self.receipts.len() == MAXIMUM_GUARDIAN_RECEIPTS {
            self.pending = Some(pending);
            return Err(GuardianReducerError::Exhausted);
        }

        let resolved_action = pending_effect_action(pending);
        let terminal = resolved_action == GuardianReducerActionV1::Cleanup;
        if terminal && !managed.all_released() {
            self.pending = Some(pending);
            return Err(GuardianReducerError::ObservationMismatch);
        }
        let mut receipt = GuardianEffectReceiptV1 {
            request_id: pending.admission.request_id(),
            sequence: pending.admission.sequence(),
            admitted_action: pending.admission.action(),
            action: resolved_action,
            admission_digest: pending.admission.digest(),
            authority_digest: pending.admission.authority.digest(),
            network_fence_digest: pending.admission.network.digest(),
            managed_snapshot_digest: managed.digest(),
            observation_digest,
            step_evidence_count: pending.step_evidence_count,
            step_evidence_anchor: pending
                .step_evidence_anchor
                .ok_or(GuardianReducerError::ObservationMismatch)?,
            last_released_boottime_nanoseconds: pending
                .released_boottime_nanoseconds
                .ok_or(GuardianReducerError::ObservationMismatch)?,
            last_released_observation_ordinal: pending
                .released_observation_ordinal
                .ok_or(GuardianReducerError::ObservationMismatch)?,
            last_observation_ordinal: pending
                .last_observation_ordinal
                .ok_or(GuardianReducerError::ObservationMismatch)?,
            worker_death_supersession_digest: pending
                .worker_death_supersession
                .map(|evidence| evidence.digest),
            terminal,
            digest: zero_digest(),
        };
        receipt.digest = receipt_digest(receipt);
        self.highest_sequence = receipt.sequence;
        self.managed = managed;
        self.network = pending.admission.network;
        if matches!(
            receipt.action,
            GuardianReducerActionV1::Arm
                | GuardianReducerActionV1::Renew
                | GuardianReducerActionV1::ReplaceWorker
                | GuardianReducerActionV1::Resume
        ) {
            self.authority = pending.admission.authority;
            self.worker_identity_digest = pending
                .admission
                .replacement_worker_digest
                .unwrap_or(pending.admission.worker_identity_digest);
            self.timer = pending.admission.timer;
        }
        self.receipts.push(receipt);
        self.terminal = terminal;
        Ok(receipt)
    }

    /// Returns the sole safe crash-recovery disposition.
    pub(crate) fn recovery_disposition(
        &self,
    ) -> Result<GuardianRecoveryDispositionV1, GuardianReducerError> {
        self.ensure_healthy()?;
        if self.terminal {
            let receipt = self
                .receipts
                .last()
                .copied()
                .ok_or(GuardianReducerError::ObservationMismatch)?;
            return Ok(GuardianRecoveryDispositionV1::Terminal(receipt));
        }
        let disposition = match self.pending {
            None => GuardianRecoveryDispositionV1::Idle,
            Some(pending) => match pending.phase {
                GuardianReducerPhaseV1::Frozen => {
                    GuardianRecoveryDispositionV1::RevalidateFrozen(pending.admission.digest())
                }
                GuardianReducerPhaseV1::EffectUnknown => {
                    GuardianRecoveryDispositionV1::RevalidateFrozen(pending.admission.digest())
                }
                GuardianReducerPhaseV1::ReleaseFrozen => {
                    GuardianRecoveryDispositionV1::ObserveOnly(pending.admission.digest())
                }
                GuardianReducerPhaseV1::PlanExposed => {
                    GuardianRecoveryDispositionV1::ObserveOnly(pending.admission.digest())
                }
                GuardianReducerPhaseV1::ReissueFrozen => {
                    GuardianRecoveryDispositionV1::RevalidateReissue(pending.admission.digest())
                }
                GuardianReducerPhaseV1::Observed => {
                    let observation_digest = pending
                        .observation_digest
                        .ok_or(GuardianReducerError::ObservationMismatch)?;
                    GuardianRecoveryDispositionV1::CommitObserved(observation_digest)
                }
            },
        };
        Ok(disposition)
    }

    /// Returns the canonical bounded reducer-state commitment.
    pub(crate) fn snapshot_digest(&self) -> ObjectDigest {
        let mut digest = Sha256::new();
        digest.update(REDUCER_DOMAIN);
        digest.update(self.authority.digest().as_bytes());
        digest.update(self.network.digest().as_bytes());
        digest.update(self.managed.digest().as_bytes());
        digest.update(self.worker_identity_digest.as_bytes());
        digest.update(self.timer.policy_digest.as_bytes());
        digest.update(self.timer.armed_boottime_nanoseconds.to_be_bytes());
        digest.update(self.timer.early_freeze_boottime_nanoseconds.to_be_bytes());
        digest.update(self.timer.hard_stop_boottime_nanoseconds.to_be_bytes());
        digest.update(self.highest_sequence.to_be_bytes());
        digest.update(self.receipt_floor_sequence.to_be_bytes());
        update_optional_digest(&mut digest, self.receipt_anchor_digest);
        match self.pending {
            None => digest.update([0]),
            Some(pending) => {
                digest.update([1, guardian_phase_code(pending.phase)]);
                digest.update(pending.admission.digest().as_bytes());
                match pending.observation_digest {
                    None => digest.update([0]),
                    Some(value) => {
                        digest.update([1]);
                        digest.update(value.as_bytes());
                    }
                }
                match pending.observed_managed {
                    None => digest.update([0]),
                    Some(value) => {
                        digest.update([1]);
                        digest.update(value.digest().as_bytes());
                    }
                }
                update_optional_u64(&mut digest, pending.released_boottime_nanoseconds);
                update_optional_u64(&mut digest, pending.released_observation_ordinal);
                update_optional_u64(&mut digest, pending.last_observation_ordinal);
                update_optional_digest(&mut digest, pending.effect_evidence_digest);
                match pending.step {
                    None => digest.update([0]),
                    Some(step) => digest.update([1, step as u8]),
                }
                digest.update(pending.next_attempt_ordinal.to_be_bytes());
                update_optional_u64(&mut digest, pending.active_attempt_ordinal);
                digest.update(pending.step_evidence_count.to_be_bytes());
                update_optional_digest(&mut digest, pending.step_evidence_anchor);
                update_optional_digest(&mut digest, pending.prior_step_evidence_anchor);
                match pending.predecessor_current {
                    None => digest.update([0]),
                    Some(current) => {
                        digest.update([1]);
                        digest.update(guardian_current_digest(current).as_bytes());
                    }
                }
                update_optional_digest(&mut digest, pending.step_attempt_digest);
                match pending.last_outcome {
                    None => digest.update([0]),
                    Some(outcome) => {
                        digest.update([1]);
                        digest.update(outcome.digest.as_bytes());
                    }
                }
                match pending.last_completed_action {
                    None => digest.update([0]),
                    Some(action) => digest.update([1, action as u8]),
                }
                match pending.last_completed_step {
                    None => digest.update([0]),
                    Some(step) => digest.update([1, step as u8]),
                }
                match pending.last_completed_predecessor {
                    None => digest.update([0]),
                    Some(current) => {
                        digest.update([1]);
                        digest.update(guardian_current_digest(current).as_bytes());
                    }
                }
                update_optional_digest(&mut digest, pending.last_completed_attempt_digest);
                update_optional_u64(&mut digest, pending.last_completed_attempt_ordinal);
                update_optional_u64(
                    &mut digest,
                    pending.last_completed_released_boottime_nanoseconds,
                );
                update_optional_u64(
                    &mut digest,
                    pending.last_completed_released_observation_ordinal,
                );
                match pending.containment_override {
                    None => digest.update([0]),
                    Some(GuardianContainmentOverrideV1::EarlyFreeze) => digest.update([1]),
                    Some(GuardianContainmentOverrideV1::Expire) => digest.update([2]),
                    Some(GuardianContainmentOverrideV1::EnforcementLoss) => digest.update([3]),
                }
                match pending.worker_death_supersession {
                    None => digest.update([0]),
                    Some(value) => {
                        digest.update([1]);
                        digest.update(value.digest.as_bytes());
                    }
                }
                for handoff in pending.release_timer_handoffs {
                    match handoff {
                        None => digest.update([0]),
                        Some(value) => {
                            digest.update([1]);
                            digest.update(value.digest.as_bytes());
                        }
                    }
                }
            }
        }
        digest.update((self.receipts.len() as u64).to_be_bytes());
        digest.update((self.compacted_receipt_index.len() as u64).to_be_bytes());
        for receipt in &self.compacted_receipt_index {
            digest.update(receipt.sequence.to_be_bytes());
            digest.update(receipt.request_id);
            digest.update([receipt.action as u8]);
            digest.update(receipt.admission_digest.as_bytes());
            digest.update(receipt.receipt_digest.as_bytes());
        }
        for receipt in &self.receipts {
            digest.update(receipt.digest().as_bytes());
        }
        digest.update([u8::from(self.terminal)]);
        digest.update([u8::from(self.poisoned)]);
        ObjectDigest::from_bytes(digest.finalize().into())
    }

    /// Freezes the complete bounded state for protected crash persistence.
    pub(crate) fn snapshot(&self) -> GuardianRecoverySnapshotV1 {
        GuardianRecoverySnapshotV1 {
            authority: self.authority,
            network: self.network,
            managed: self.managed,
            worker_identity_digest: self.worker_identity_digest,
            timer: self.timer,
            highest_sequence: self.highest_sequence,
            receipt_floor_sequence: self.receipt_floor_sequence,
            receipt_anchor_digest: self.receipt_anchor_digest,
            pending: self.pending,
            compacted_receipt_index: self.compacted_receipt_index.clone(),
            receipts: self.receipts.clone(),
            terminal: self.terminal,
            poisoned: self.poisoned,
            digest: self.snapshot_digest(),
        }
    }

    /// Replays one exact protected-journal edge against its predecessor.
    pub(super) fn validates_journal_successor(
        prior: &GuardianRecoverySnapshotV1,
        next: &GuardianRecoverySnapshotV1,
    ) -> bool {
        let Ok(mut reducer) = Self::recover(prior.clone()) else {
            return false;
        };
        if prior.digest == next.digest {
            return guardian_snapshot_matches(&reducer, next);
        }
        if next.receipt_floor_sequence > prior.receipt_floor_sequence {
            let Ok(authority) = reducer.mint_compaction(next.receipt_floor_sequence) else {
                return false;
            };
            return reducer.compact_receipts(authority).is_ok()
                && guardian_snapshot_matches(&reducer, next);
        }
        match (prior.pending, next.pending) {
            (None, Some(pending)) => {
                reducer.begin(pending.admission).is_ok()
                    && guardian_snapshot_matches(&reducer, next)
            }
            (Some(pending), None) if pending.phase == GuardianReducerPhaseV1::Observed => {
                reducer.commit_observed().is_ok() && guardian_snapshot_matches(&reducer, next)
            }
            (Some(prior_pending), Some(next_pending))
                if prior_pending.admission.digest() == next_pending.admission.digest() =>
            {
                replay_guardian_pending_edge(&mut reducer, prior_pending, next_pending)
                    && guardian_snapshot_matches(&reducer, next)
            }
            _ => false,
        }
    }

    /// Compacts an exact receipt prefix only with protected journal authority.
    pub(crate) fn compact_receipts(
        &mut self,
        authority: ProtectedGuardianCompactionV1,
    ) -> Result<(), GuardianReducerError> {
        self.ensure_healthy()?;
        if self.pending.is_some()
            || authority.snapshot_digest != self.snapshot_digest()
            || authority.through_sequence <= self.receipt_floor_sequence
            || authority.through_sequence >= self.highest_sequence
        {
            return Err(GuardianReducerError::CurrentnessMismatch);
        }
        let removed = self
            .receipts
            .iter()
            .take_while(|receipt| receipt.sequence <= authority.through_sequence)
            .count();
        if removed == 0 || self.receipts[removed - 1].sequence != authority.through_sequence {
            return Err(GuardianReducerError::InvalidTransition);
        }
        let expected_anchor =
            guardian_compacted_anchor(&self.compacted_receipt_index, &self.receipts[..removed]);
        if authority.anchor_digest != expected_anchor
            || authority.replay_index_digest
                != guardian_replay_index(&self.compacted_receipt_index, &self.receipts)
        {
            return Err(GuardianReducerError::ObservationMismatch);
        }
        if self.compacted_receipt_index.len().saturating_add(removed)
            > MAXIMUM_COMPACTED_GUARDIAN_RECEIPTS
        {
            return Err(GuardianReducerError::Exhausted);
        }
        self.compacted_receipt_index
            .extend(self.receipts.drain(..removed).map(compact_guardian_receipt));
        self.receipt_floor_sequence = authority.through_sequence;
        self.receipt_anchor_digest = Some(expected_anchor);
        Ok(())
    }

    /// Derives compaction authority from this exact in-memory protected head.
    fn mint_compaction(
        &self,
        through_sequence: u64,
    ) -> Result<ProtectedGuardianCompactionV1, GuardianReducerError> {
        self.ensure_healthy()?;
        let removed = self
            .receipts
            .iter()
            .take_while(|receipt| receipt.sequence <= through_sequence)
            .count();
        if self.pending.is_some()
            || through_sequence <= self.receipt_floor_sequence
            || through_sequence >= self.highest_sequence
            || removed == 0
            || self.receipts[removed - 1].sequence != through_sequence
        {
            return Err(GuardianReducerError::CurrentnessMismatch);
        }
        Ok(ProtectedGuardianCompactionV1 {
            snapshot_digest: self.snapshot_digest(),
            through_sequence,
            anchor_digest: guardian_compacted_anchor(
                &self.compacted_receipt_index,
                &self.receipts[..removed],
            ),
            replay_index_digest: guardian_replay_index(
                &self.compacted_receipt_index,
                &self.receipts,
            ),
        })
    }

    fn ensure_healthy(&self) -> Result<(), GuardianReducerError> {
        if self.poisoned {
            Err(GuardianReducerError::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn guardian_snapshot_matches(
    reducer: &GuardianAuthorityReducerV1,
    expected: &GuardianRecoverySnapshotV1,
) -> bool {
    let candidate = reducer.snapshot();
    codec::encode_snapshot(&candidate).ok() == codec::encode_snapshot(expected).ok()
}

fn replay_guardian_pending_edge(
    reducer: &mut GuardianAuthorityReducerV1,
    prior: PendingGuardianEffectV1,
    next: PendingGuardianEffectV1,
) -> bool {
    match (prior.phase, next.phase) {
        (
            GuardianReducerPhaseV1::Frozen | GuardianReducerPhaseV1::ReissueFrozen,
            GuardianReducerPhaseV1::EffectUnknown,
        ) => next
            .predecessor_current
            .is_some_and(|current| reducer.prepare_effect(current).is_ok()),
        (GuardianReducerPhaseV1::EffectUnknown, GuardianReducerPhaseV1::ReleaseFrozen) => {
            let Some(mut current) = prior.predecessor_current else {
                return false;
            };
            let (Some(released_time), Some(released_ordinal), Some(step_attempt_digest)) = (
                next.released_boottime_nanoseconds,
                next.released_observation_ordinal,
                prior.step_attempt_digest,
            ) else {
                return false;
            };
            current.durable_reducer_digest = reducer.snapshot_digest();
            let Ok(managed) = GuardianManagedSnapshotV1::new(
                current.managed.assignment,
                current.managed.entries,
                released_time,
                current.managed.session_digest,
                current.managed.currentness_digest,
            ) else {
                return false;
            };
            current.managed = managed;
            current.managed_snapshot_digest = managed.digest();
            current.observed_boottime_nanoseconds = released_time;
            current.observation_ordinal = released_ordinal;
            let effect = GuardianEffectPreflightV1 {
                admission_digest: prior.admission.digest(),
                step_attempt_digest,
                recovery_digest: reducer.snapshot_digest(),
            };
            reducer.freeze_release(effect, current).is_ok()
        }
        (GuardianReducerPhaseV1::ReleaseFrozen, GuardianReducerPhaseV1::PlanExposed) => {
            let Some(mut current) = prior.predecessor_current else {
                return false;
            };
            let (Some(released_time), Some(released_ordinal), Some(step_attempt_digest)) = (
                prior.released_boottime_nanoseconds,
                prior.released_observation_ordinal,
                prior.step_attempt_digest,
            ) else {
                return false;
            };
            let Some(observation_ordinal) = released_ordinal.checked_add(1) else {
                return false;
            };
            current.durable_reducer_digest = reducer.snapshot_digest();
            let Ok(managed) = GuardianManagedSnapshotV1::new(
                current.managed.assignment,
                current.managed.entries,
                released_time,
                current.managed.session_digest,
                current.managed.currentness_digest,
            ) else {
                return false;
            };
            current.managed = managed;
            current.managed_snapshot_digest = managed.digest();
            current.observed_boottime_nanoseconds = released_time;
            current.observation_ordinal = observation_ordinal;
            let release_digest =
                guardian_plan_release_digest(prior.admission.digest(), step_attempt_digest);
            let release = GuardianReleasePreflightV1 {
                admission_digest: prior.admission.digest(),
                step_attempt_digest,
                release_digest,
                recovery_digest: reducer.snapshot_digest(),
            };
            reducer.release_effect(release, current).is_ok()
        }
        (
            GuardianReducerPhaseV1::ReleaseFrozen | GuardianReducerPhaseV1::PlanExposed,
            GuardianReducerPhaseV1::Observed | GuardianReducerPhaseV1::ReissueFrozen,
        ) if next.last_outcome.map(|outcome| outcome.digest)
            != prior.last_outcome.map(|outcome| outcome.digest) =>
        {
            next.last_outcome
                .is_some_and(|outcome| reducer.observe(outcome).is_ok())
        }
        (
            GuardianReducerPhaseV1::EffectUnknown,
            GuardianReducerPhaseV1::Frozen | GuardianReducerPhaseV1::ReissueFrozen,
        ) if next.worker_death_supersession.is_none() => {
            let Some(mut current) = prior.predecessor_current else {
                return false;
            };
            let Some(ordinal) = current.observation_ordinal.checked_add(1) else {
                return false;
            };
            current.durable_reducer_digest = reducer.snapshot_digest();
            current.observation_ordinal = ordinal;
            reducer.revalidate_unreleased(current).is_ok()
        }
        (
            GuardianReducerPhaseV1::EffectUnknown | GuardianReducerPhaseV1::ReleaseFrozen,
            GuardianReducerPhaseV1::ReissueFrozen,
        ) if prior.worker_death_supersession.is_none()
            && next.worker_death_supersession.is_some() =>
        {
            next.worker_death_supersession
                .is_some_and(|evidence| reducer.supersede_worker_death(evidence).is_ok())
        }
        (GuardianReducerPhaseV1::ReleaseFrozen, GuardianReducerPhaseV1::ReissueFrozen) => next
            .release_timer_handoffs
            .iter()
            .zip(prior.release_timer_handoffs.iter())
            .find_map(|(next, prior)| prior.is_none().then_some(*next).flatten())
            .is_some_and(|handoff| {
                let release = GuardianReleasePreflightV1 {
                    admission_digest: prior.admission.digest(),
                    step_attempt_digest: handoff.step_attempt_digest,
                    release_digest: handoff.release_digest,
                    recovery_digest: reducer.snapshot_digest(),
                };
                reducer
                    .handoff_release_timer(release, handoff.current)
                    .is_ok()
            }),
        _ => false,
    }
}

fn valid_recovered_guardian_pending(
    pending: PendingGuardianEffectV1,
    prior_network_digest: ObjectDigest,
) -> bool {
    if pending.containment_override.is_some()
        && pending.last_outcome.is_none()
        && pending.worker_death_supersession.is_none()
        && pending.release_timer_handoffs.iter().all(Option::is_none)
        || pending.worker_death_supersession.is_some()
            && pending.containment_override != Some(GuardianContainmentOverrideV1::EnforcementLoss)
    {
        return false;
    }
    if let (
        Some(outcome),
        Some(completed_action),
        Some(step),
        Some(predecessor),
        Some(attempt_digest),
    ) = (
        pending.last_outcome,
        pending.last_completed_action,
        pending.last_completed_step,
        pending.last_completed_predecessor,
        pending.last_completed_attempt_digest,
    ) {
        let Some(attempt_ordinal) = pending.last_completed_attempt_ordinal else {
            return false;
        };
        let expected_worker_identity = pending
            .admission
            .replacement_worker_digest
            .unwrap_or(pending.admission.worker_identity_digest);
        if !valid_recovered_current(pending.admission, prior_network_digest, predecessor)
            || outcome.admission_digest != pending.admission.digest()
            || outcome.authority_digest != pending.admission.authority.digest()
            || outcome.network_fence_digest != pending.admission.network.digest()
            || outcome.worker_identity_digest != expected_worker_identity
            || outcome.worker_resource_digest.as_bytes() == &[0; 32]
            || outcome.worker_currentness_digest.as_bytes() == &[0; 32]
            || outcome.first_snapshot_digest.as_bytes() == &[0; 32]
            || outcome.first_snapshot_digest != outcome.second_snapshot_digest
            || outcome.effect_evidence_digest.as_bytes() == &[0; 32]
            || attempt_ordinal != pending.step_evidence_count
            || !outcome
                .managed
                .matches_network_resource(pending.admission.network)
            || outcome.managed.session_digest != pending.admission.network.session_digest
            || outcome.managed.currentness_digest != pending.admission.network.currentness_digest
            || !outcome.managed.does_not_regress_from(predecessor.managed)
            || !valid_managed_action_progress(
                completed_action,
                predecessor.managed,
                outcome.managed,
            )
            || pending
                .last_completed_released_observation_ordinal
                .is_none_or(|ordinal| outcome.observation_ordinal <= ordinal)
            || pending
                .last_completed_released_boottime_nanoseconds
                .is_none_or(|released| outcome.managed.observed_boottime_nanoseconds() < released)
            || outcome.release_digest
                != guardian_plan_release_digest(pending.admission.digest(), attempt_digest)
            || outcome.step_attempt_digest != attempt_digest
            || outcome.predecessor_digest != guardian_current_digest(predecessor)
            || outcome.observation_ordinal <= predecessor.observation_ordinal
            || attempt_digest
                != guardian_step_attempt_digest(
                    pending.admission.digest(),
                    step,
                    attempt_ordinal,
                    predecessor,
                )
            || pending.step_evidence_anchor
                != Some(guardian_step_evidence_record_digest(
                    pending.step_evidence_count - 1,
                    pending.prior_step_evidence_anchor,
                    completed_action,
                    step,
                    attempt_ordinal,
                    attempt_digest,
                    pending.last_completed_released_boottime_nanoseconds,
                    pending.last_completed_released_observation_ordinal,
                    outcome,
                ))
            || !valid_guardian_step_progress(step, predecessor, &outcome)
            || next_effect_step(completed_action, predecessor) != Some(step)
            || pending.phase == GuardianReducerPhaseV1::ReissueFrozen
                && next_effect_step_from_outcome(pending_effect_action(pending), &outcome).is_none()
            || pending.phase == GuardianReducerPhaseV1::Observed
                && (completed_action != pending_effect_action(pending)
                    || !guardian_terminal_outcome_valid(
                        pending_effect_action(pending),
                        pending.admission,
                        &outcome,
                    )
                    || next_effect_step_from_outcome(pending_effect_action(pending), &outcome)
                        .is_some())
        {
            return false;
        }
    }
    let Some(current) = pending.predecessor_current else {
        return match pending.phase {
            GuardianReducerPhaseV1::Frozen => pending.containment_override.is_none(),
            GuardianReducerPhaseV1::ReissueFrozen => {
                let protected_source = latest_protected_reissue_current(pending);
                match (pending.last_outcome, protected_source) {
                    (Some(outcome), Some(source))
                        if source.observation_ordinal > outcome.observation_ordinal =>
                    {
                        pending.observed_managed == Some(source.managed)
                            && next_effect_step(pending_effect_action(pending), source).is_some()
                    }
                    (Some(outcome), _) => {
                        pending.observed_managed == Some(outcome.managed)
                            && next_effect_step_from_outcome(
                                pending_effect_action(pending),
                                &outcome,
                            )
                            .is_some()
                    }
                    (None, Some(source)) => {
                        pending.observed_managed == Some(source.managed)
                            && next_effect_step(pending_effect_action(pending), source).is_some()
                    }
                    (None, None) => false,
                }
            }
            _ => false,
        };
    };
    let Some(step) = pending.step else {
        return false;
    };
    let mut predecessor_pending = pending;
    predecessor_pending.phase = GuardianReducerPhaseV1::EffectUnknown;
    predecessor_pending.observed_managed = Some(current.managed);
    let protected_source = latest_protected_reissue_current(pending);
    let predecessor_follows_source = match (pending.last_outcome, protected_source) {
        (Some(outcome), Some(source))
            if source.observation_ordinal > outcome.observation_ordinal =>
        {
            current.observation_ordinal > source.observation_ordinal
                && same_guardian_residual(source, current)
        }
        (Some(outcome), _) => guardian_current_matches_outcome(current, outcome),
        (None, Some(source)) => {
            current.observation_ordinal > source.observation_ordinal
                && same_guardian_residual(source, current)
        }
        (None, None) => true,
    };
    if !valid_recovered_current(pending.admission, prior_network_digest, current)
        || (matches!(
            pending.phase,
            GuardianReducerPhaseV1::EffectUnknown
                | GuardianReducerPhaseV1::ReleaseFrozen
                | GuardianReducerPhaseV1::PlanExposed
        ) && Some(current.managed) != pending.observed_managed)
        || pending.phase != GuardianReducerPhaseV1::Observed && !predecessor_follows_source
        || validate_guardian_effect_current(
            current.durable_reducer_digest,
            prior_network_digest,
            predecessor_pending,
            current,
        )
        .is_err()
        || next_effect_step(pending_effect_action(pending), current) != Some(step)
    {
        return false;
    }
    match pending.phase {
        GuardianReducerPhaseV1::EffectUnknown => {
            pending.released_boottime_nanoseconds.is_none()
                && pending.released_observation_ordinal.is_none()
        }
        GuardianReducerPhaseV1::ReleaseFrozen
        | GuardianReducerPhaseV1::PlanExposed
        | GuardianReducerPhaseV1::Observed => {
            matches!(
                (
                    pending.released_boottime_nanoseconds,
                    pending.released_observation_ordinal,
                ),
                (Some(boottime), Some(ordinal))
                    if boottime >= current.observed_boottime_nanoseconds
                        && ordinal > current.observation_ordinal
            )
        }
        _ => false,
    }
}

fn guardian_terminal_outcome_valid(
    action: GuardianReducerActionV1,
    admission: GuardianEffectAdmissionV1,
    outcome: &ProtectedGuardianOutcomeV1,
) -> bool {
    let observed_time = outcome.managed.observed_boottime_nanoseconds();
    match action {
        GuardianReducerActionV1::Arm | GuardianReducerActionV1::Renew => {
            !outcome.network_default_drop
                && !outcome.payload_frozen
                && !outcome.payload_stopped
                && outcome.admitted_worker_live
                && outcome.renewal_timer_current
                && outcome.network_lease_gate_current
                && outcome.payload_released
                && outcome.managed.allows_active_runtime()
                && observed_time < admission.timer.early_freeze_boottime_nanoseconds()
        }
        GuardianReducerActionV1::Resume => {
            !outcome.network_default_drop
                && !outcome.payload_frozen
                && !outcome.payload_stopped
                && outcome.admitted_worker_live
                && outcome.renewal_timer_current
                && outcome.network_lease_gate_current
                && outcome.payload_released
                && outcome.managed.allows_active_runtime()
                && observed_time < admission.timer.early_freeze_boottime_nanoseconds()
        }
        GuardianReducerActionV1::EarlyFreeze => {
            !outcome.network_default_drop
                && outcome.admitted_worker_live
                && outcome.payload_frozen
                && !outcome.payload_stopped
                && outcome.managed.allows_early_frozen_runtime()
                && observed_time >= admission.timer.early_freeze_boottime_nanoseconds()
                && observed_time < admission.timer.hard_stop_boottime_nanoseconds()
        }
        GuardianReducerActionV1::ReplaceWorker => {
            outcome.old_worker_dead
                && outcome.admitted_worker_live
                && outcome.network_default_drop
                && outcome.payload_stopped
                && !outcome.payload_released
                && outcome.managed.allows_contained_runtime()
                && observed_time < admission.timer.early_freeze_boottime_nanoseconds()
        }
        GuardianReducerActionV1::Revoke | GuardianReducerActionV1::EnforcementLoss => {
            outcome.network_default_drop
                && outcome.payload_stopped
                && !outcome.payload_released
                && outcome.managed.allows_contained_runtime()
        }
        GuardianReducerActionV1::Expire => {
            outcome.network_default_drop
                && outcome.payload_stopped
                && !outcome.payload_released
                && outcome.managed.allows_contained_runtime()
                && observed_time >= admission.timer.hard_stop_boottime_nanoseconds()
        }
        GuardianReducerActionV1::Cleanup => {
            outcome.network_default_drop
                && outcome.payload_stopped
                && !outcome.payload_released
                && outcome.old_worker_dead
                && !outcome.admitted_worker_live
                && outcome.payload_frozen
                && outcome.managed.all_released()
        }
    }
}

fn valid_guardian_receipt_action(receipt: GuardianEffectReceiptV1) -> bool {
    if receipt.action == receipt.admitted_action {
        return receipt.worker_death_supersession_digest.is_none()
            || receipt.action == GuardianReducerActionV1::EnforcementLoss;
    }
    match receipt.action {
        GuardianReducerActionV1::EarlyFreeze | GuardianReducerActionV1::Expire => {
            receipt.worker_death_supersession_digest.is_none()
        }
        GuardianReducerActionV1::EnforcementLoss => receipt
            .worker_death_supersession_digest
            .is_some_and(|digest| digest.as_bytes() != &[0; 32]),
        _ => false,
    }
}

fn validate_network_authority(
    authority: GuardianAuthoritySnapshotV1,
    network: GuardianNetworkFenceV1,
) -> Result<(), GuardianReducerError> {
    if authority.assignment() != network.assignment()
        || authority.lease_generation() != network.lease_generation()
        || authority.lease_digest() != network.lease_digest()
        || authority.fail_stop_boottime_nanoseconds() != network.fail_stop_boottime_nanoseconds()
        || authority.host_boot_id() != network.kernel_boot_id
    {
        return Err(GuardianReducerError::NetworkFenceMismatch);
    }
    Ok(())
}

fn valid_authority_snapshot(authority: GuardianAuthoritySnapshotV1) -> bool {
    authority.node.as_bytes() != &[0; 16]
        && authority.desired_generation != 0
        && authority.lease_generation != 0
        && authority.host_boot_id != [0; 16]
        && authority.clock_provenance != [0; 16]
        && authority.fail_stop_boottime_nanoseconds != 0
        && [
            authority.plan_digest,
            authority.lease_digest,
            authority.durable_state_digest,
            authority.digest,
        ]
        .iter()
        .all(|digest| digest.as_bytes() != &[0; 32])
        && authority.digest == authority_digest(authority)
}

fn timer_policy_digest(margin_nanoseconds: u64) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(TIMER_POLICY_DOMAIN);
    digest.update(margin_nanoseconds.to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn valid_cause(
    value: ProtectedGuardianCauseEvidenceV1,
    expected_kind: GuardianCauseKindV1,
    authority: GuardianAuthoritySnapshotV1,
    network: GuardianNetworkFenceV1,
) -> bool {
    if value.kind != expected_kind
        || value.assignment != authority.assignment()
        || value.authority_digest != authority.digest()
        || value.session_digest != network.session_digest
        || value.currentness_digest != network.currentness_digest
        || value.source_digest.as_bytes() == &[0; 32]
        || value.observation_ordinal == 0
    {
        return false;
    }
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.guardian.protected-cause.v1\0");
    digest.update([value.kind as u8]);
    digest.update(value.assignment.sandbox().as_bytes());
    digest.update(value.assignment.incarnation().as_bytes());
    digest.update(value.assignment.epoch().get().to_be_bytes());
    digest.update(value.assignment.digest().as_bytes());
    digest.update(value.authority_digest.as_bytes());
    digest.update(value.source_digest.as_bytes());
    digest.update(value.session_digest.as_bytes());
    digest.update(value.currentness_digest.as_bytes());
    digest.update(value.observation_ordinal.to_be_bytes());
    value.digest == ObjectDigest::from_bytes(digest.finalize().into())
}

fn validate_admission_transition(
    reducer: &GuardianAuthorityReducerV1,
    admission: GuardianEffectAdmissionV1,
) -> Result<(), GuardianReducerError> {
    if !admission
        .managed
        .matches_admitted_network_resource(admission.network)
    {
        return Err(GuardianReducerError::NetworkFenceMismatch);
    }

    let same_current = admission.authority == reducer.authority
        && admission
            .managed
            .refreshes_same_managed_state(reducer.managed)
        && admission.worker_identity_digest == reducer.worker_identity_digest;
    let same_timer = admission.timer == reducer.timer;
    let same_kernel = admission.network.has_same_kernel_identity(reducer.network);
    let valid = match admission.action() {
        GuardianReducerActionV1::Arm => {
            reducer.highest_sequence == 0 && same_current && same_kernel && same_timer
        }
        GuardianReducerActionV1::Renew => {
            admission.authority.assignment() == reducer.authority.assignment()
                && admission.authority.node() == reducer.authority.node()
                && admission.authority.desired_generation()
                    == reducer.authority.desired_generation()
                && admission.authority.lease_generation() > reducer.authority.lease_generation()
                && admission.authority.fail_stop_boottime_nanoseconds()
                    > reducer.authority.fail_stop_boottime_nanoseconds()
                && same_kernel
                && admission
                    .managed
                    .rebinds_same_managed_state(reducer.managed, admission.network)
                && admission.worker_identity_digest == reducer.worker_identity_digest
                && admission.timer.policy_digest == reducer.timer.policy_digest
                && admission.timer.armed_boottime_nanoseconds
                    >= reducer.timer.armed_boottime_nanoseconds
        }
        GuardianReducerActionV1::Revoke
        | GuardianReducerActionV1::Expire
        | GuardianReducerActionV1::EnforcementLoss
        | GuardianReducerActionV1::Cleanup => same_current && same_kernel && same_timer,
        GuardianReducerActionV1::EarlyFreeze | GuardianReducerActionV1::ReplaceWorker => {
            same_current && admission.network == reducer.network && same_timer
        }
        GuardianReducerActionV1::Resume => {
            let predecessor = reducer.receipts.last().copied();
            let predecessor_action_valid = predecessor.is_some_and(|receipt| {
                matches!(
                    receipt.action,
                    GuardianReducerActionV1::EarlyFreeze
                        | GuardianReducerActionV1::Expire
                        | GuardianReducerActionV1::EnforcementLoss
                        | GuardianReducerActionV1::ReplaceWorker
                ) && Some(receipt.digest) == admission.predecessor_receipt_digest
            });
            let newer_authority_required = predecessor
                .is_some_and(|receipt| receipt.action != GuardianReducerActionV1::ReplaceWorker);
            predecessor_action_valid
                && admission.authority.assignment() == reducer.authority.assignment()
                && admission.authority.node() == reducer.authority.node()
                && admission.authority.desired_generation()
                    == reducer.authority.desired_generation()
                && (!newer_authority_required
                    || admission.authority.lease_generation()
                        > reducer.authority.lease_generation())
                && admission.authority.fail_stop_boottime_nanoseconds()
                    > reducer.managed.observed_boottime_nanoseconds()
                && same_kernel
                && admission
                    .managed
                    .rebinds_same_managed_state(reducer.managed, admission.network)
                && admission.worker_identity_digest == reducer.worker_identity_digest
                && admission.timer.policy_digest == reducer.timer.policy_digest
                && admission.timer.armed_boottime_nanoseconds
                    >= reducer.timer.armed_boottime_nanoseconds
        }
    };
    if valid {
        Ok(())
    } else {
        Err(GuardianReducerError::InvalidTransition)
    }
}

fn valid_managed_action_progress(
    action: GuardianReducerActionV1,
    prior: GuardianManagedSnapshotV1,
    current: GuardianManagedSnapshotV1,
) -> bool {
    let unchanged = |index: usize| {
        let left = prior.entries[index];
        let right = current.entries[index];
        left.domain == right.domain
            && left.generation == right.generation
            && left.resource_digest == right.resource_digest
            && left.observation_digest == right.observation_digest
            && left.catalog_digest == right.catalog_digest
            && left.currentness_digest == right.currentness_digest
            && left.status == right.status
    };

    match action {
        GuardianReducerActionV1::Arm | GuardianReducerActionV1::Resume => {
            unchanged(1) && unchanged(2)
        }
        GuardianReducerActionV1::Renew => unchanged(0) && unchanged(1) && unchanged(2),
        GuardianReducerActionV1::EarlyFreeze => unchanged(1) && unchanged(2) && unchanged(3),
        GuardianReducerActionV1::Revoke
        | GuardianReducerActionV1::Expire
        | GuardianReducerActionV1::EnforcementLoss => unchanged(1) && unchanged(2),
        GuardianReducerActionV1::ReplaceWorker => {
            unchanged(0) && unchanged(1) && unchanged(2) && unchanged(3)
        }
        GuardianReducerActionV1::Cleanup => true,
    }
}

fn append_guardian_step_evidence(
    pending: &mut PendingGuardianEffectV1,
    outcome: &ProtectedGuardianOutcomeV1,
) -> Result<(), GuardianReducerError> {
    let step = pending
        .step
        .ok_or(GuardianReducerError::ObservationMismatch)?;
    let predecessor = pending
        .predecessor_current
        .ok_or(GuardianReducerError::ObservationMismatch)?;
    let attempt_digest = pending
        .step_attempt_digest
        .ok_or(GuardianReducerError::ObservationMismatch)?;
    let completed_action = pending_effect_action(*pending);
    let prior_anchor = pending.step_evidence_anchor;
    let attempt_ordinal = pending
        .active_attempt_ordinal
        .ok_or(GuardianReducerError::ObservationMismatch)?;
    let released_boottime = pending.released_boottime_nanoseconds;
    let released_ordinal = pending.released_observation_ordinal;
    pending.step_evidence_anchor = Some(guardian_step_evidence_record_digest(
        pending.step_evidence_count,
        prior_anchor,
        completed_action,
        step,
        attempt_ordinal,
        attempt_digest,
        released_boottime,
        released_ordinal,
        *outcome,
    ));
    pending.prior_step_evidence_anchor = prior_anchor;
    pending.step_evidence_count = pending
        .step_evidence_count
        .checked_add(1)
        .ok_or(GuardianReducerError::Exhausted)?;
    pending.next_attempt_ordinal = pending
        .next_attempt_ordinal
        .checked_add(1)
        .ok_or(GuardianReducerError::Exhausted)?;
    pending.last_observation_ordinal = Some(outcome.observation_ordinal);
    pending.effect_evidence_digest = Some(outcome.effect_evidence_digest);
    pending.last_completed_step = Some(step);
    pending.last_completed_action = Some(completed_action);
    pending.last_completed_predecessor = Some(predecessor);
    pending.last_completed_attempt_digest = Some(attempt_digest);
    pending.last_completed_attempt_ordinal = Some(attempt_ordinal);
    pending.last_completed_released_boottime_nanoseconds = released_boottime;
    pending.last_completed_released_observation_ordinal = released_ordinal;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn guardian_step_evidence_record_digest(
    prior_count: u64,
    prior_anchor: Option<ObjectDigest>,
    action: GuardianReducerActionV1,
    step: GuardianEffectStepV1,
    attempt_ordinal: u64,
    attempt_digest: ObjectDigest,
    released_boottime_nanoseconds: Option<u64>,
    released_observation_ordinal: Option<u64>,
    outcome: ProtectedGuardianOutcomeV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(STEP_EVIDENCE_DOMAIN);
    digest.update(prior_count.to_be_bytes());
    update_optional_digest(&mut digest, prior_anchor);
    digest.update([action as u8]);
    digest.update([step as u8]);
    digest.update(attempt_ordinal.to_be_bytes());
    digest.update(attempt_digest.as_bytes());
    update_optional_u64(&mut digest, released_boottime_nanoseconds);
    update_optional_u64(&mut digest, released_observation_ordinal);
    digest.update(outcome.effect_evidence_digest.as_bytes());
    digest.update(outcome.digest.as_bytes());
    digest.update(outcome.observation_ordinal.to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn guardian_step_attempt_digest(
    admission_digest: ObjectDigest,
    step: GuardianEffectStepV1,
    attempt_ordinal: u64,
    predecessor: ProtectedGuardianCurrentV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.guardian.step-attempt.v1\0");
    digest.update(admission_digest.as_bytes());
    digest.update([step as u8]);
    digest.update(attempt_ordinal.to_be_bytes());
    digest.update(guardian_current_digest(predecessor).as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn guardian_plan_release_digest(
    admission_digest: ObjectDigest,
    step_attempt_digest: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(RELEASE_DOMAIN);
    digest.update(admission_digest.as_bytes());
    digest.update(step_attempt_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn guardian_worker_death_supersession_digest(
    evidence: ProtectedGuardianWorkerDeathSupersessionV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.guardian.worker-death-supersession.v1\0");
    digest.update(evidence.admission_digest.as_bytes());
    digest.update([evidence.superseded_action as u8]);
    digest.update([evidence.step as u8]);
    digest.update(evidence.attempt_ordinal.to_be_bytes());
    digest.update(evidence.step_attempt_digest.as_bytes());
    digest.update(guardian_current_digest(evidence.predecessor_current).as_bytes());
    digest.update(evidence.death_evidence_digest.as_bytes());
    digest.update(guardian_current_digest(evidence.current).as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn guardian_release_timer_handoff_digest(handoff: GuardianReleaseTimerHandoffV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.guardian.release-timer-handoff.v1\0");
    digest.update([handoff.source_action as u8, handoff.target_action as u8]);
    digest.update([handoff.step as u8]);
    digest.update(handoff.attempt_ordinal.to_be_bytes());
    digest.update(handoff.step_attempt_digest.as_bytes());
    digest.update(handoff.release_digest.as_bytes());
    digest.update(guardian_current_digest(handoff.predecessor_current).as_bytes());
    digest.update(handoff.released_boottime_nanoseconds.to_be_bytes());
    digest.update(handoff.released_observation_ordinal.to_be_bytes());
    digest.update(guardian_current_digest(handoff.current).as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn valid_release_timer_handoffs(
    pending: PendingGuardianEffectV1,
    prior_network_digest: ObjectDigest,
) -> bool {
    let Some(mut expected_attempt_ordinal) = pending.step_evidence_count.checked_add(1) else {
        return false;
    };
    let expected_first_source_action = pre_handoff_source_action(pending);
    let mut absent_seen = false;
    let mut prior_observation_ordinal = 0;
    let mut prior_handoff: Option<GuardianReleaseTimerHandoffV1> = None;
    for handoff in pending.release_timer_handoffs {
        let Some(handoff) = handoff else {
            absent_seen = true;
            continue;
        };
        if absent_seen
            || handoff.attempt_ordinal != expected_attempt_ordinal
            || handoff.attempt_ordinal >= pending.next_attempt_ordinal
            || !matches!(
                (handoff.source_action, handoff.target_action),
                (
                    GuardianReducerActionV1::Arm
                        | GuardianReducerActionV1::Renew
                        | GuardianReducerActionV1::ReplaceWorker
                        | GuardianReducerActionV1::Resume,
                    GuardianReducerActionV1::EarlyFreeze | GuardianReducerActionV1::Expire,
                ) | (
                    GuardianReducerActionV1::EarlyFreeze,
                    GuardianReducerActionV1::Expire,
                )
            )
            || match prior_handoff {
                Some(prior) => {
                    handoff.source_action != prior.target_action
                        || handoff.predecessor_current.observation_ordinal
                            <= prior.current.observation_ordinal
                        || !same_guardian_residual(prior.current, handoff.predecessor_current)
                }
                None => Some(handoff.source_action) != expected_first_source_action,
            }
            || handoff.step_attempt_digest
                != guardian_step_attempt_digest(
                    pending.admission.digest(),
                    handoff.step,
                    handoff.attempt_ordinal,
                    handoff.predecessor_current,
                )
            || handoff.release_digest
                != guardian_plan_release_digest(
                    pending.admission.digest(),
                    handoff.step_attempt_digest,
                )
            || !valid_recovered_current(
                pending.admission,
                prior_network_digest,
                handoff.predecessor_current,
            )
            || !valid_recovered_current(pending.admission, prior_network_digest, handoff.current)
            || next_effect_step(handoff.source_action, handoff.predecessor_current)
                != Some(handoff.step)
            || handoff.released_boottime_nanoseconds
                < handoff.predecessor_current.observed_boottime_nanoseconds
            || handoff.released_observation_ordinal
                <= handoff.predecessor_current.observation_ordinal
            || handoff.current.observed_boottime_nanoseconds < handoff.released_boottime_nanoseconds
            || handoff.current.observation_ordinal <= handoff.released_observation_ordinal
            || !same_guardian_residual(handoff.predecessor_current, handoff.current)
            || handoff.current.observation_ordinal <= prior_observation_ordinal
            || handoff.target_action
                != if handoff.current.observed_boottime_nanoseconds
                    >= pending.admission.timer.hard_stop_boottime_nanoseconds()
                {
                    GuardianReducerActionV1::Expire
                } else if handoff.current.observed_boottime_nanoseconds
                    >= pending.admission.timer.early_freeze_boottime_nanoseconds()
                {
                    GuardianReducerActionV1::EarlyFreeze
                } else {
                    return false;
                }
            || handoff.digest != guardian_release_timer_handoff_digest(handoff)
        {
            return false;
        }
        let Some(next_expected_attempt_ordinal) = expected_attempt_ordinal.checked_add(1) else {
            return false;
        };
        expected_attempt_ordinal = next_expected_attempt_ordinal;
        prior_observation_ordinal = handoff.current.observation_ordinal;
        prior_handoff = Some(handoff);
    }

    let Some(last) = pending.release_timer_handoffs.iter().flatten().last() else {
        return true;
    };
    match pending.worker_death_supersession {
        Some(evidence) => {
            evidence.predecessor_current.observation_ordinal > last.current.observation_ordinal
                && same_guardian_residual(last.current, evidence.predecessor_current)
        }
        None => pending_effect_action(pending) == last.target_action,
    }
}

fn pre_handoff_source_action(pending: PendingGuardianEffectV1) -> Option<GuardianReducerActionV1> {
    let Some(outcome) = pending.last_outcome else {
        return pending
            .last_completed_action
            .is_none()
            .then_some(pending.admission.action());
    };
    let completed_action = pending.last_completed_action?;
    let observed = outcome.managed.observed_boottime_nanoseconds();
    let admitted_active_action = matches!(
        pending.admission.action(),
        GuardianReducerActionV1::Arm
            | GuardianReducerActionV1::Renew
            | GuardianReducerActionV1::ReplaceWorker
            | GuardianReducerActionV1::Resume
    );
    let completed_early_freeze_lineage =
        pending
            .last_completed_predecessor
            .is_some_and(|predecessor| {
                completed_action == GuardianReducerActionV1::EarlyFreeze
                    && admitted_active_action
                    && pending.step_evidence_count >= 2
                    && pending.prior_step_evidence_anchor.is_some()
                    && predecessor.observed_boottime_nanoseconds
                        >= pending.admission.timer.early_freeze_boottime_nanoseconds()
                    && predecessor.observed_boottime_nanoseconds
                        < pending.admission.timer.hard_stop_boottime_nanoseconds()
                    && observed >= predecessor.observed_boottime_nanoseconds
                    && observed < pending.admission.timer.hard_stop_boottime_nanoseconds()
                    && matches!(
                        pending.containment_override,
                        Some(
                            GuardianContainmentOverrideV1::EarlyFreeze
                                | GuardianContainmentOverrideV1::Expire
                        )
                    )
            });
    let completed_action_has_lineage =
        completed_action == pending.admission.action() || completed_early_freeze_lineage;
    if !completed_action_has_lineage {
        return None;
    }
    let active_action = matches!(
        completed_action,
        GuardianReducerActionV1::Arm
            | GuardianReducerActionV1::Renew
            | GuardianReducerActionV1::ReplaceWorker
            | GuardianReducerActionV1::Resume
    );
    if observed >= pending.admission.timer.hard_stop_boottime_nanoseconds()
        && (active_action || completed_action == GuardianReducerActionV1::EarlyFreeze)
    {
        Some(GuardianReducerActionV1::Expire)
    } else if observed >= pending.admission.timer.early_freeze_boottime_nanoseconds()
        && active_action
    {
        Some(GuardianReducerActionV1::EarlyFreeze)
    } else {
        Some(completed_action)
    }
}

fn latest_protected_reissue_current(
    pending: PendingGuardianEffectV1,
) -> Option<ProtectedGuardianCurrentV1> {
    pending
        .release_timer_handoffs
        .iter()
        .flatten()
        .map(|handoff| handoff.current)
        .chain(
            pending
                .worker_death_supersession
                .map(|evidence| evidence.current),
        )
        .max_by_key(|current| current.observation_ordinal)
}

fn valid_worker_death_supersession(
    admission: GuardianEffectAdmissionV1,
    evidence: ProtectedGuardianWorkerDeathSupersessionV1,
) -> bool {
    evidence.digest == guardian_worker_death_supersession_digest(evidence)
        && evidence.admission_digest == admission.digest()
        && evidence.attempt_ordinal != 0
        && evidence.step_attempt_digest
            == guardian_step_attempt_digest(
                admission.digest(),
                evidence.step,
                evidence.attempt_ordinal,
                evidence.predecessor_current,
            )
        && evidence.death_evidence_digest.as_bytes() != &[0; 32]
        && evidence.current.observation_ordinal > evidence.predecessor_current.observation_ordinal
        && evidence.predecessor_current.admission_digest == admission.digest()
        && evidence.predecessor_current.authority_digest == admission.authority.digest()
        && evidence.predecessor_current.admitted_network_fence_digest == admission.network.digest()
        && evidence.predecessor_current.managed_snapshot_digest
            == evidence.predecessor_current.managed.digest()
        && evidence.current.admission_digest == admission.digest()
        && evidence.current.authority_digest == admission.authority.digest()
        && evidence.current.admitted_network_fence_digest == admission.network.digest()
        && evidence.current.managed_snapshot_digest == evidence.current.managed.digest()
        && evidence.predecessor_current.worker_identity_digest
            == admission
                .replacement_worker_digest
                .unwrap_or(admission.worker_identity_digest)
        && evidence
            .predecessor_current
            .worker_resource_digest
            .as_bytes()
            != &[0; 32]
        && evidence
            .predecessor_current
            .worker_currentness_digest
            .as_bytes()
            != &[0; 32]
        && evidence.current.worker_resource_digest.as_bytes() != &[0; 32]
        && evidence.current.worker_currentness_digest.as_bytes() != &[0; 32]
        && evidence.predecessor_current.current_worker_live
        && !evidence.predecessor_current.admitted_worker_absent
        && evidence.current.worker_identity_digest
            == evidence.predecessor_current.worker_identity_digest
        && evidence.current.worker_resource_digest
            != evidence.predecessor_current.worker_resource_digest
        && evidence.current.worker_currentness_digest
            != evidence.predecessor_current.worker_currentness_digest
        && !evidence.current.current_worker_live
        && evidence.current.admitted_worker_absent
        && evidence.current.old_worker_dead
        && evidence
            .current
            .managed
            .refreshes_same_managed_state(evidence.predecessor_current.managed)
        && evidence.current.network_default_drop
            == evidence.predecessor_current.network_default_drop
        && evidence.current.renewal_timer_current
            == evidence.predecessor_current.renewal_timer_current
        && evidence.current.network_lease_gate_current
            == evidence.predecessor_current.network_lease_gate_current
        && evidence.current.payload_frozen == evidence.predecessor_current.payload_frozen
        && evidence.current.payload_stopped == evidence.predecessor_current.payload_stopped
        && evidence.current.payload_released == evidence.predecessor_current.payload_released
        && next_effect_step(evidence.superseded_action, evidence.predecessor_current)
            == Some(evidence.step)
        && next_effect_step(GuardianReducerActionV1::EnforcementLoss, evidence.current).is_some()
}

fn valid_recovered_current(
    admission: GuardianEffectAdmissionV1,
    prior_network_digest: ObjectDigest,
    current: ProtectedGuardianCurrentV1,
) -> bool {
    current.admission_digest == admission.digest()
        && current.durable_reducer_digest.as_bytes() != &[0; 32]
        && current.authority_digest == admission.authority.digest()
        && current.prior_network_fence_digest == prior_network_digest
        && current.admitted_network_fence_digest == admission.network.digest()
        && current.managed_snapshot_digest == current.managed.digest()
        && current.managed.assignment == admission.authority.assignment()
        && current.managed.session_digest == admission.network.session_digest
        && current.managed.currentness_digest == admission.network.currentness_digest
        && current.managed.matches_network_resource(admission.network)
        && current.host_boot_id == admission.timer.host_boot_id
        && current.clock_provenance == admission.timer.clock_provenance
        && current.observed_boottime_nanoseconds != 0
        && current.observed_boottime_nanoseconds == current.managed.observed_boottime_nanoseconds()
        && current.observed_boottime_nanoseconds >= admission.timer.armed_boottime_nanoseconds
        && current.observation_ordinal != 0
        && admission
            .cause_evidence
            .is_none_or(|cause| current.observation_ordinal > cause.observation_ordinal)
        && current.worker_identity_digest
            == admission
                .replacement_worker_digest
                .unwrap_or(admission.worker_identity_digest)
        && current.worker_resource_digest.as_bytes() != &[0; 32]
        && current.worker_currentness_digest.as_bytes() != &[0; 32]
        && current.current_worker_live != current.admitted_worker_absent
}

fn valid_superseded_action_source(
    pending: PendingGuardianEffectV1,
    superseded_action: GuardianReducerActionV1,
) -> bool {
    if let Some(handoff) = pending.release_timer_handoffs.iter().flatten().last() {
        return superseded_action == handoff.target_action;
    }
    let Some(outcome) = pending.last_outcome else {
        return superseded_action == pending.admission.action();
    };
    let observed = outcome.managed.observed_boottime_nanoseconds();
    if observed >= pending.admission.timer.hard_stop_boottime_nanoseconds() {
        superseded_action == GuardianReducerActionV1::Expire
    } else if observed >= pending.admission.timer.early_freeze_boottime_nanoseconds()
        && matches!(
            pending.admission.action(),
            GuardianReducerActionV1::Arm
                | GuardianReducerActionV1::Renew
                | GuardianReducerActionV1::ReplaceWorker
                | GuardianReducerActionV1::Resume
        )
    {
        superseded_action == GuardianReducerActionV1::EarlyFreeze
    } else {
        superseded_action == pending.admission.action()
    }
}

fn pending_effect_action(pending: PendingGuardianEffectV1) -> GuardianReducerActionV1 {
    match pending.containment_override {
        None => pending.admission.action(),
        Some(GuardianContainmentOverrideV1::EarlyFreeze) => GuardianReducerActionV1::EarlyFreeze,
        Some(GuardianContainmentOverrideV1::Expire) => GuardianReducerActionV1::Expire,
        Some(GuardianContainmentOverrideV1::EnforcementLoss) => {
            GuardianReducerActionV1::EnforcementLoss
        }
    }
}

fn valid_guardian_step_progress(
    step: GuardianEffectStepV1,
    prior: ProtectedGuardianCurrentV1,
    outcome: &ProtectedGuardianOutcomeV1,
) -> bool {
    let worker_resource_valid = match step {
        GuardianEffectStepV1::StartGuardianWorker | GuardianEffectStepV1::VerifyOldWorkerDead => {
            outcome.worker_identity_digest == prior.worker_identity_digest
                && outcome.worker_resource_digest != prior.worker_resource_digest
                && outcome.worker_currentness_digest != prior.worker_currentness_digest
        }
        _ => {
            outcome.worker_identity_digest == prior.worker_identity_digest
                && outcome.worker_resource_digest == prior.worker_resource_digest
                && outcome.worker_currentness_digest == prior.worker_currentness_digest
        }
    };
    if !worker_resource_valid {
        return false;
    }

    let target_domain = match step {
        GuardianEffectStepV1::RequestPayloadFreeze
        | GuardianEffectStepV1::StopPayload
        | GuardianEffectStepV1::ReleasePayload
        | GuardianEffectStepV1::TraverseHost => Some(GuardianManagedDomainV1::Host),
        GuardianEffectStepV1::ProgramNetworkLeaseGate
        | GuardianEffectStepV1::DefaultDropNetwork
        | GuardianEffectStepV1::TraverseNetwork => Some(GuardianManagedDomainV1::Network),
        GuardianEffectStepV1::TraverseStorage => Some(GuardianManagedDomainV1::Storage),
        GuardianEffectStepV1::TraverseMount => Some(GuardianManagedDomainV1::Mount),
        GuardianEffectStepV1::StartGuardianWorker
        | GuardianEffectStepV1::VerifyOldWorkerDead
        | GuardianEffectStepV1::ProgramRenewalTimer
        | GuardianEffectStepV1::VerifyCompleteState => None,
    };
    if prior
        .managed
        .entries
        .iter()
        .zip(outcome.managed.entries)
        .any(|(left, right)| {
            Some(left.domain) != target_domain
                && (left.generation != right.generation
                    || left.resource_digest != right.resource_digest
                    || left.observation_digest != right.observation_digest
                    || left.catalog_digest != right.catalog_digest
                    || left.currentness_digest != right.currentness_digest
                    || left.status != right.status)
        })
    {
        return false;
    }
    if let Some(domain) = target_domain {
        let index = domain as usize;
        let left = prior.managed.entries[index];
        let right = outcome.managed.entries[index];
        let expected_status = match step {
            GuardianEffectStepV1::StartGuardianWorker | GuardianEffectStepV1::ReleasePayload => {
                GuardianManagedStatusV1::Active
            }
            GuardianEffectStepV1::ProgramNetworkLeaseGate => GuardianManagedStatusV1::Active,
            GuardianEffectStepV1::DefaultDropNetwork
            | GuardianEffectStepV1::RequestPayloadFreeze
            | GuardianEffectStepV1::StopPayload => GuardianManagedStatusV1::Contained,
            GuardianEffectStepV1::TraverseHost
            | GuardianEffectStepV1::TraverseStorage
            | GuardianEffectStepV1::TraverseMount
            | GuardianEffectStepV1::TraverseNetwork => right.status,
            _ => return false,
        };
        let cleanup_status = matches!(
            right.status,
            GuardianManagedStatusV1::Absent | GuardianManagedStatusV1::Released
        );
        let status_valid = if matches!(
            step,
            GuardianEffectStepV1::TraverseHost
                | GuardianEffectStepV1::TraverseStorage
                | GuardianEffectStepV1::TraverseMount
                | GuardianEffectStepV1::TraverseNetwork
        ) {
            cleanup_status
        } else {
            right.status == expected_status
        };
        let cleanup_step = matches!(
            step,
            GuardianEffectStepV1::TraverseHost
                | GuardianEffectStepV1::TraverseStorage
                | GuardianEffectStepV1::TraverseMount
                | GuardianEffectStepV1::TraverseNetwork
        );
        if !status_valid
            || right.generation <= left.generation
            || right.observation_digest == left.observation_digest
            || right.observation_digest != outcome.effect_evidence_digest
            || !cleanup_step && right.resource_digest != left.resource_digest
            || cleanup_step && right.resource_digest == left.resource_digest
            || right.catalog_digest != left.catalog_digest
            || right.currentness_digest != left.currentness_digest
        {
            return false;
        }
    }

    match step {
        GuardianEffectStepV1::StartGuardianWorker => {
            !prior.current_worker_live
                && prior.admitted_worker_absent
                && outcome.admitted_worker_live
                && outcome.old_worker_dead == prior.old_worker_dead
                && same_network_and_payload_controls(prior, outcome)
        }
        GuardianEffectStepV1::ProgramRenewalTimer => {
            !prior.renewal_timer_current
                && outcome.renewal_timer_current
                && same_except_timer(prior, outcome)
        }
        GuardianEffectStepV1::ProgramNetworkLeaseGate => {
            !prior.network_lease_gate_current
                && outcome.network_lease_gate_current
                && !outcome.network_default_drop
                && same_worker_payload_and_timer(prior, outcome)
        }
        GuardianEffectStepV1::DefaultDropNetwork => {
            !prior.network_default_drop
                && outcome.network_default_drop
                && !outcome.network_lease_gate_current
                && same_worker_and_payload(prior, outcome)
                && outcome.renewal_timer_current == prior.renewal_timer_current
        }
        GuardianEffectStepV1::RequestPayloadFreeze => {
            !prior.payload_frozen
                && outcome.payload_frozen
                && !outcome.payload_released
                && same_worker_and_network(prior, outcome)
                && outcome.renewal_timer_current == prior.renewal_timer_current
                && outcome.payload_stopped == prior.payload_stopped
        }
        GuardianEffectStepV1::StopPayload => {
            !prior.payload_stopped
                && outcome.payload_stopped
                && !outcome.payload_released
                && same_worker_and_network(prior, outcome)
                && outcome.renewal_timer_current == prior.renewal_timer_current
        }
        GuardianEffectStepV1::VerifyOldWorkerDead => {
            !prior.old_worker_dead
                && outcome.old_worker_dead
                && !outcome.admitted_worker_live
                && same_network_and_payload_controls(prior, outcome)
        }
        GuardianEffectStepV1::ReleasePayload => {
            outcome.admitted_worker_live
                && outcome.renewal_timer_current
                && outcome.network_lease_gate_current
                && outcome.payload_released
                && !outcome.network_default_drop
        }
        GuardianEffectStepV1::TraverseHost
        | GuardianEffectStepV1::TraverseStorage
        | GuardianEffectStepV1::TraverseMount
        | GuardianEffectStepV1::TraverseNetwork => {
            outcome.admitted_worker_live == prior.current_worker_live
                && outcome.old_worker_dead == prior.old_worker_dead
                && same_network_and_payload_controls(prior, outcome)
        }
        GuardianEffectStepV1::VerifyCompleteState => false,
    }
}

fn same_network_and_payload_controls(
    prior: ProtectedGuardianCurrentV1,
    outcome: &ProtectedGuardianOutcomeV1,
) -> bool {
    outcome.network_default_drop == prior.network_default_drop
        && outcome.network_lease_gate_current == prior.network_lease_gate_current
        && outcome.renewal_timer_current == prior.renewal_timer_current
        && outcome.payload_frozen == prior.payload_frozen
        && outcome.payload_stopped == prior.payload_stopped
        && outcome.payload_released == prior.payload_released
}

fn same_except_timer(
    prior: ProtectedGuardianCurrentV1,
    outcome: &ProtectedGuardianOutcomeV1,
) -> bool {
    outcome.admitted_worker_live == prior.current_worker_live
        && outcome.old_worker_dead == prior.old_worker_dead
        && outcome.network_default_drop == prior.network_default_drop
        && outcome.network_lease_gate_current == prior.network_lease_gate_current
        && outcome.payload_frozen == prior.payload_frozen
        && outcome.payload_stopped == prior.payload_stopped
        && outcome.payload_released == prior.payload_released
}

fn same_worker_payload_and_timer(
    prior: ProtectedGuardianCurrentV1,
    outcome: &ProtectedGuardianOutcomeV1,
) -> bool {
    outcome.admitted_worker_live == prior.current_worker_live
        && outcome.old_worker_dead == prior.old_worker_dead
        && outcome.renewal_timer_current == prior.renewal_timer_current
        && outcome.payload_frozen == prior.payload_frozen
        && outcome.payload_stopped == prior.payload_stopped
        && outcome.payload_released == prior.payload_released
}

fn same_worker_and_payload(
    prior: ProtectedGuardianCurrentV1,
    outcome: &ProtectedGuardianOutcomeV1,
) -> bool {
    outcome.admitted_worker_live == prior.current_worker_live
        && outcome.old_worker_dead == prior.old_worker_dead
        && outcome.payload_frozen == prior.payload_frozen
        && outcome.payload_stopped == prior.payload_stopped
        && outcome.payload_released == prior.payload_released
}

fn same_worker_and_network(
    prior: ProtectedGuardianCurrentV1,
    outcome: &ProtectedGuardianOutcomeV1,
) -> bool {
    outcome.admitted_worker_live == prior.current_worker_live
        && outcome.old_worker_dead == prior.old_worker_dead
        && outcome.network_default_drop == prior.network_default_drop
        && outcome.network_lease_gate_current == prior.network_lease_gate_current
}

fn guardian_current_digest(current: ProtectedGuardianCurrentV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.guardian.protected-current.v1\0");
    for value in [
        current.admission_digest,
        current.durable_reducer_digest,
        current.authority_digest,
        current.prior_network_fence_digest,
        current.admitted_network_fence_digest,
        current.managed_snapshot_digest,
    ] {
        digest.update(value.as_bytes());
    }
    digest.update(current.host_boot_id);
    digest.update(current.clock_provenance);
    digest.update(current.observed_boottime_nanoseconds.to_be_bytes());
    digest.update(current.observation_ordinal.to_be_bytes());
    digest.update(current.worker_identity_digest.as_bytes());
    digest.update(current.worker_resource_digest.as_bytes());
    digest.update(current.worker_currentness_digest.as_bytes());
    digest.update([
        u8::from(current.current_worker_live),
        u8::from(current.old_worker_dead),
        u8::from(current.admitted_worker_absent),
        u8::from(current.network_default_drop),
        u8::from(current.renewal_timer_current),
        u8::from(current.network_lease_gate_current),
        u8::from(current.payload_frozen),
        u8::from(current.payload_stopped),
        u8::from(current.payload_released),
    ]);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn same_guardian_residual(
    left: ProtectedGuardianCurrentV1,
    right: ProtectedGuardianCurrentV1,
) -> bool {
    right.managed.refreshes_same_managed_state(left.managed)
        && left.worker_identity_digest == right.worker_identity_digest
        && left.worker_resource_digest == right.worker_resource_digest
        && left.worker_currentness_digest == right.worker_currentness_digest
        && left.current_worker_live == right.current_worker_live
        && left.old_worker_dead == right.old_worker_dead
        && left.admitted_worker_absent == right.admitted_worker_absent
        && left.network_default_drop == right.network_default_drop
        && left.renewal_timer_current == right.renewal_timer_current
        && left.network_lease_gate_current == right.network_lease_gate_current
        && left.payload_frozen == right.payload_frozen
        && left.payload_stopped == right.payload_stopped
        && left.payload_released == right.payload_released
}

fn guardian_current_matches_outcome(
    current: ProtectedGuardianCurrentV1,
    outcome: ProtectedGuardianOutcomeV1,
) -> bool {
    current.observation_ordinal > outcome.observation_ordinal
        && current
            .managed
            .refreshes_same_managed_state(outcome.managed)
        && current.worker_identity_digest == outcome.worker_identity_digest
        && current.worker_resource_digest == outcome.worker_resource_digest
        && current.worker_currentness_digest == outcome.worker_currentness_digest
        && current.current_worker_live == outcome.admitted_worker_live
        && current.old_worker_dead == outcome.old_worker_dead
        && current.admitted_worker_absent == !outcome.admitted_worker_live
        && current.network_default_drop == outcome.network_default_drop
        && current.renewal_timer_current == outcome.renewal_timer_current
        && current.network_lease_gate_current == outcome.network_lease_gate_current
        && current.payload_frozen == outcome.payload_frozen
        && current.payload_stopped == outcome.payload_stopped
        && current.payload_released == outcome.payload_released
}

const fn guardian_phase_code(phase: GuardianReducerPhaseV1) -> u8 {
    match phase {
        GuardianReducerPhaseV1::Frozen => 0,
        GuardianReducerPhaseV1::EffectUnknown => 1,
        GuardianReducerPhaseV1::ReleaseFrozen => 2,
        GuardianReducerPhaseV1::ReissueFrozen => 3,
        GuardianReducerPhaseV1::Observed => 4,
        GuardianReducerPhaseV1::PlanExposed => 5,
    }
}

fn update_optional_u64(digest: &mut Sha256, value: Option<u64>) {
    match value {
        None => digest.update([0; 9]),
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
    }
}

fn update_optional_digest(digest: &mut Sha256, value: Option<ObjectDigest>) {
    match value {
        None => digest.update([0; 33]),
        Some(value) => {
            digest.update([1]);
            digest.update(value.as_bytes());
        }
    }
}

fn guardian_compacted_anchor(
    compacted: &[CompactedGuardianReceiptV1],
    newly_compacted: &[GuardianEffectReceiptV1],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.guardian.compacted-anchor.v1\0");
    digest.update(((compacted.len() + newly_compacted.len()) as u64).to_be_bytes());
    for receipt in compacted {
        digest.update(receipt.sequence.to_be_bytes());
        digest.update(receipt.request_id);
        digest.update([receipt.action as u8]);
        digest.update(receipt.admission_digest.as_bytes());
        digest.update(receipt.receipt_digest.as_bytes());
    }
    for receipt in newly_compacted {
        digest.update(receipt.sequence.to_be_bytes());
        digest.update(receipt.request_id);
        digest.update([receipt.action as u8]);
        digest.update(receipt.admission_digest.as_bytes());
        digest.update(receipt.digest.as_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn guardian_replay_index(
    compacted: &[CompactedGuardianReceiptV1],
    retained: &[GuardianEffectReceiptV1],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.guardian.replay-index.v1\0");
    digest.update(((compacted.len() + retained.len()) as u64).to_be_bytes());
    for receipt in compacted {
        digest.update(receipt.sequence.to_be_bytes());
        digest.update(receipt.request_id);
        digest.update([receipt.action as u8]);
        digest.update(receipt.admission_digest.as_bytes());
        digest.update(receipt.receipt_digest.as_bytes());
    }
    for receipt in retained {
        digest.update(receipt.sequence.to_be_bytes());
        digest.update(receipt.request_id);
        digest.update([receipt.action as u8]);
        digest.update(receipt.admission_digest.as_bytes());
        digest.update(receipt.digest.as_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn encode_guardian_checkpoint(
    snapshot: &GuardianRecoverySnapshotV1,
    payload: &[u8],
) -> Result<Vec<u8>, GuardianReducerError> {
    let indexed_count = snapshot.compacted_receipt_index.len() + snapshot.receipts.len();
    let count = u32::try_from(indexed_count).map_err(|_| GuardianReducerError::Exhausted)?;
    let capacity = 8usize
        .checked_add(2 + 8 + 1 + 32 + 32 + 4)
        .and_then(|value| value.checked_add(indexed_count.checked_mul(88)?))
        .and_then(|value| value.checked_add(4 + payload.len()))
        .ok_or(GuardianReducerError::Exhausted)?;
    if capacity > MAXIMUM_GUARDIAN_CHECKPOINT_BYTES {
        return Err(GuardianReducerError::Exhausted);
    }
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(b"AOSGRDV1");
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&snapshot.receipt_floor_sequence.to_be_bytes());
    match snapshot.receipt_anchor_digest {
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0; 32]);
        }
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(value.as_bytes());
        }
    }
    bytes.extend_from_slice(snapshot.digest.as_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    for receipt in &snapshot.compacted_receipt_index {
        bytes.extend_from_slice(&receipt.sequence.to_be_bytes());
        bytes.extend_from_slice(&receipt.request_id);
        bytes.extend_from_slice(receipt.admission_digest.as_bytes());
        bytes.extend_from_slice(receipt.receipt_digest.as_bytes());
    }
    for receipt in &snapshot.receipts {
        bytes.extend_from_slice(&receipt.sequence.to_be_bytes());
        bytes.extend_from_slice(&receipt.request_id);
        bytes.extend_from_slice(receipt.admission_digest.as_bytes());
        bytes.extend_from_slice(receipt.digest.as_bytes());
    }
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| GuardianReducerError::Exhausted)?;
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn compact_guardian_receipt(receipt: GuardianEffectReceiptV1) -> CompactedGuardianReceiptV1 {
    CompactedGuardianReceiptV1 {
        request_id: receipt.request_id,
        sequence: receipt.sequence,
        action: receipt.action,
        admission_digest: receipt.admission_digest,
        receipt_digest: receipt.digest,
    }
}

fn decode_guardian_checkpoint_header(
    bytes: &[u8],
) -> Result<(u64, Option<ObjectDigest>, ObjectDigest, usize), GuardianReducerError> {
    if bytes.len() < 87
        || bytes.len() > MAXIMUM_GUARDIAN_CHECKPOINT_BYTES
        || &bytes[..8] != b"AOSGRDV1"
        || bytes[8..10] != 1u16.to_be_bytes()
    {
        return Err(GuardianReducerError::ObservationMismatch);
    }
    let floor = u64::from_be_bytes(
        bytes[10..18]
            .try_into()
            .map_err(|_| GuardianReducerError::ObservationMismatch)?,
    );
    let anchor_bytes: [u8; 32] = bytes[19..51]
        .try_into()
        .map_err(|_| GuardianReducerError::ObservationMismatch)?;
    let anchor = match bytes[18] {
        0 if anchor_bytes == [0; 32] => None,
        1 if anchor_bytes != [0; 32] => Some(ObjectDigest::from_bytes(anchor_bytes)),
        _ => return Err(GuardianReducerError::ObservationMismatch),
    };
    let snapshot_digest = ObjectDigest::from_bytes(
        bytes[51..83]
            .try_into()
            .map_err(|_| GuardianReducerError::ObservationMismatch)?,
    );
    let count = u32::from_be_bytes(
        bytes[83..87]
            .try_into()
            .map_err(|_| GuardianReducerError::ObservationMismatch)?,
    ) as usize;
    let payload_length_offset = 87usize.saturating_add(count.saturating_mul(88));
    if bytes.len() < payload_length_offset.saturating_add(4) {
        return Err(GuardianReducerError::ObservationMismatch);
    }
    Ok((floor, anchor, snapshot_digest, count))
}

fn guardian_checkpoint_payload(bytes: &[u8]) -> Result<&[u8], GuardianReducerError> {
    let (_, _, _, count) = decode_guardian_checkpoint_header(bytes)?;
    let offset = 87usize
        .checked_add(
            count
                .checked_mul(88)
                .ok_or(GuardianReducerError::ObservationMismatch)?,
        )
        .ok_or(GuardianReducerError::ObservationMismatch)?;
    let length = u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .map_err(|_| GuardianReducerError::ObservationMismatch)?,
    ) as usize;
    let end = offset
        .checked_add(4)
        .and_then(|value| value.checked_add(length))
        .ok_or(GuardianReducerError::ObservationMismatch)?;
    if end != bytes.len() {
        return Err(GuardianReducerError::ObservationMismatch);
    }
    Ok(&bytes[offset + 4..end])
}

const fn zero_digest() -> ObjectDigest {
    ObjectDigest::from_bytes([0; 32])
}
