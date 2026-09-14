//! Dormant Network lifecycle authority and recovery reducer.
//!
//! This module closes Arm, Renew, Disarm, and Destroy over one exact namespace,
//! link, bpffs, tc-BPF, assignment, lease, session, and currentness identity.
//! It performs no kernel operation and exposes no service method. Effect plans
//! require opaque protected-current evidence for which this source partition
//! deliberately supplies no constructor.

use aos_sandbox_core::{BrokerAssignment, ObjectDigest};
use sha2::{Digest as _, Sha256};

use crate::namespace_catalog::{
    NetworkNamespaceIdentityV1, NetworkNamespaceLifecycleActionV1,
    NetworkNamespaceObservedStateKindV1, NetworkNamespaceObservedStateV1,
};

mod codec;
mod validation;

use validation::{
    next_effect_step, residual_effect_changed, valid_link_identity, valid_tc_identity,
    validate_action_step_result, validate_operation, validate_residual, validate_step_progress,
};

const FENCE_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-fence.v1\0";
const OBJECT_IDENTITY_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-objects.v1\0";
const INTENT_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-intent.v1\0";
const CLEANUP_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-cleanup.v1\0";
const RESIDUAL_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-residual.v1\0";
const STEP_ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-step-attempt.v1\0";
const RELEASE_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-plan-release.v1\0";
const STEP_EVIDENCE_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-step-evidence.v1\0";
const PENDING_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-pending.v1\0";
const OBSERVATION_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-observation.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-receipt.v1\0";
const SNAPSHOT_DOMAIN: &[u8] = b"aos.sandbox.network.lifecycle-reducer.v1\0";
const MAXIMUM_RETAINED_RECEIPTS: usize = 4_096;
const MAXIMUM_COMPACTED_RECEIPTS: usize = 16_384;
const MAXIMUM_EFFECT_ATTEMPTS: u64 = 256;
const MAXIMUM_RECOVERY_CHECKPOINT_BYTES: usize = 8 * 1024 * 1024;

/// Reports a closed lifecycle reducer rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum NetworkLifecycleReducerError {
    /// An identity, generation, deadline, or digest is unspecified.
    #[error("Network lifecycle reducer input contains a zero sentinel")]
    Unspecified,
    /// An operation does not match its exact prior and desired state.
    #[error("Network lifecycle operation is incompatible with its state")]
    InvalidTransition,
    /// A request identity was reused for different immutable intent.
    #[error("Network lifecycle request equivocation")]
    Equivocation,
    /// An operation sequence is stale or skips the next exact value.
    #[error("Network lifecycle operation sequence is not the next value")]
    StaleSequence,
    /// Another operation is unresolved and must be observed after restart.
    #[error("Network lifecycle operation is already pending or ambiguous")]
    Pending,
    /// Protected current evidence differs from the frozen intent.
    #[error("Network lifecycle protected-current evidence mismatched")]
    CurrentnessMismatch,
    /// The retained ownership lease cannot authorize the requested effect.
    #[error("Network lifecycle ownership lease is stale or expired")]
    LeaseMismatch,
    /// A post-effect observation is incomplete or belongs to another attempt.
    #[error("Network lifecycle cleanup observation is incomplete or mismatched")]
    ObservationMismatch,
    /// A destroyed namespace handle cannot be resurrected.
    #[error("Network lifecycle namespace is terminally destroyed")]
    TerminalDestroyed,
    /// Sequence arithmetic exhausted the v1 range.
    #[error("Network lifecycle operation sequence is exhausted")]
    SequenceExhausted,
    /// The bounded idempotency receipt history is full.
    #[error("Network lifecycle receipt history is exhausted")]
    ReceiptHistoryExhausted,
    /// An invalid protected observation poisoned the in-memory reducer.
    #[error("Network lifecycle reducer is poisoned")]
    Poisoned,
}

/// Binds one authority decision to assignment, lease, session, and currentness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkLifecycleFenceV1 {
    assignment: BrokerAssignment,
    ownership_lease_digest: ObjectDigest,
    lease_generation: u64,
    fail_stop_boottime_nanoseconds: u64,
    session_digest: ObjectDigest,
    currentness_digest: ObjectDigest,
    digest: ObjectDigest,
}

impl NetworkLifecycleFenceV1 {
    /// Constructs one fully specified lifecycle authority fence.
    pub(crate) fn new(
        assignment: BrokerAssignment,
        ownership_lease_digest: ObjectDigest,
        lease_generation: u64,
        fail_stop_boottime_nanoseconds: u64,
        session_digest: ObjectDigest,
        currentness_digest: ObjectDigest,
    ) -> Result<Self, NetworkLifecycleReducerError> {
        if ownership_lease_digest.as_bytes() == &[0; 32]
            || lease_generation == 0
            || fail_stop_boottime_nanoseconds == 0
            || session_digest.as_bytes() == &[0; 32]
            || currentness_digest.as_bytes() == &[0; 32]
        {
            return Err(NetworkLifecycleReducerError::Unspecified);
        }

        let digest = fence_digest(
            assignment,
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
            session_digest,
            currentness_digest,
        );
        Ok(Self {
            assignment,
            ownership_lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
            session_digest,
            currentness_digest,
            digest,
        })
    }

    /// Returns the exact assignment protected by this fence.
    pub(crate) const fn assignment(self) -> BrokerAssignment {
        self.assignment
    }

    /// Returns the accepted ownership-lease digest.
    pub(crate) const fn ownership_lease_digest(self) -> ObjectDigest {
        self.ownership_lease_digest
    }

    /// Returns the monotonic accepted lease generation.
    pub(crate) const fn lease_generation(self) -> u64 {
        self.lease_generation
    }

    /// Returns the exclusive kernel fail-stop deadline.
    pub(crate) const fn fail_stop_boottime_nanoseconds(self) -> u64 {
        self.fail_stop_boottime_nanoseconds
    }

    /// Returns the exact authenticated local-session commitment.
    pub(crate) const fn session_digest(self) -> ObjectDigest {
        self.session_digest
    }

    /// Returns the exact protected-current observation commitment.
    pub(crate) const fn currentness_digest(self) -> ObjectDigest {
        self.currentness_digest
    }

    /// Returns the canonical commitment to every fence field.
    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Identifies either an isolated loopback or an exact veth pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkLifecycleLinkIdentityV1 {
    /// Identifies a loopback-only namespace.
    Isolated {
        /// Exact namespace-local loopback interface index.
        loopback_ifindex: u32,
    },
    /// Identifies both ends of the assignment's veth pair.
    Veth {
        /// Namespace-local loopback interface index.
        loopback_ifindex: u32,
        /// Host-side interface index.
        host_ifindex: u32,
        /// Sandbox-side interface index.
        sandbox_ifindex: u32,
        /// Host-side link identity commitment, including peer and MAC.
        host_link_digest: ObjectDigest,
        /// Sandbox-side link identity commitment, including peer and MAC.
        sandbox_link_digest: ObjectDigest,
    },
}

/// Identifies the complete fixed tc-BPF lease-gate installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkLifecycleTcIdentityV1 {
    /// No tc lease gate is permitted for an isolated namespace.
    Absent,
    /// The exact pinned gate is present on both veth directions.
    LeaseGate {
        /// Device identity of the retained bpffs mount.
        bpffs_device: u64,
        /// Inode identity of the exact pinned-object directory.
        bpffs_inode: u64,
        /// Host-ingress tc program identity.
        host_ingress_program_id: u32,
        /// Host-egress tc program identity.
        host_egress_program_id: u32,
        /// Lease map identity shared by the fixed programs.
        lease_map_id: u32,
        /// Measured immutable tc-BPF artifact commitment.
        artifact_digest: ObjectDigest,
        /// Loader binding over programs, map, and artifact.
        loader_binding_digest: ObjectDigest,
    },
}

/// Binds the complete reusable kernel identity of one Network handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkLifecycleKernelIdentityV1 {
    namespace: NetworkNamespaceIdentityV1,
    kernel_plan_digest: ObjectDigest,
    packet_policy_digest: ObjectDigest,
    links: NetworkLifecycleLinkIdentityV1,
    tc: NetworkLifecycleTcIdentityV1,
    digest: ObjectDigest,
}

impl NetworkLifecycleKernelIdentityV1 {
    /// Constructs an exact namespace, link, bpffs, and tc policy identity.
    pub(crate) fn new(
        namespace: NetworkNamespaceIdentityV1,
        kernel_plan_digest: ObjectDigest,
        packet_policy_digest: ObjectDigest,
        links: NetworkLifecycleLinkIdentityV1,
        tc: NetworkLifecycleTcIdentityV1,
    ) -> Result<Self, NetworkLifecycleReducerError> {
        if kernel_plan_digest.as_bytes() == &[0; 32]
            || packet_policy_digest.as_bytes() == &[0; 32]
            || !valid_link_identity(links)
            || !valid_tc_identity(links, tc)
        {
            return Err(NetworkLifecycleReducerError::Unspecified);
        }

        let digest = kernel_identity_digest(
            namespace,
            kernel_plan_digest,
            packet_policy_digest,
            links,
            tc,
        );
        Ok(Self {
            namespace,
            kernel_plan_digest,
            packet_policy_digest,
            links,
            tc,
            digest,
        })
    }

    /// Returns the exact physical namespace identity.
    pub(crate) const fn namespace(self) -> NetworkNamespaceIdentityV1 {
        self.namespace
    }

    /// Returns the commitment to every kernel identity field.
    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Stores one immutable lifecycle operation before any effect can run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkLifecycleIntentV1 {
    request_id: [u8; 16],
    operation_sequence: u64,
    action: NetworkNamespaceLifecycleActionV1,
    prior_resource_digest: ObjectDigest,
    prior_catalog_digest: ObjectDigest,
    prior_state: NetworkNamespaceObservedStateV1,
    desired_state: NetworkNamespaceObservedStateV1,
    kernel: NetworkLifecycleKernelIdentityV1,
    fence: NetworkLifecycleFenceV1,
    digest: ObjectDigest,
}

impl NetworkLifecycleIntentV1 {
    /// Constructs a canonical exact intent for Arm, Renew, Disarm, or Destroy.
    pub(crate) fn new(
        request_id: [u8; 16],
        operation_sequence: u64,
        action: NetworkNamespaceLifecycleActionV1,
        prior_resource_digest: ObjectDigest,
        prior_catalog_digest: ObjectDigest,
        prior_state: NetworkNamespaceObservedStateV1,
        desired_state: NetworkNamespaceObservedStateV1,
        kernel: NetworkLifecycleKernelIdentityV1,
        fence: NetworkLifecycleFenceV1,
    ) -> Result<Self, NetworkLifecycleReducerError> {
        if request_id == [0; 16]
            || operation_sequence == 0
            || prior_resource_digest.as_bytes() == &[0; 32]
            || prior_catalog_digest.as_bytes() == &[0; 32]
        {
            return Err(NetworkLifecycleReducerError::Unspecified);
        }
        validate_operation(action, prior_state, desired_state, fence)?;

        let digest = intent_digest(
            request_id,
            operation_sequence,
            action,
            prior_resource_digest,
            prior_catalog_digest,
            prior_state,
            desired_state,
            kernel.digest(),
            fence.digest(),
        );
        Ok(Self {
            request_id,
            operation_sequence,
            action,
            prior_resource_digest,
            prior_catalog_digest,
            prior_state,
            desired_state,
            kernel,
            fence,
            digest,
        })
    }

    /// Returns the request's idempotency identity.
    pub(crate) const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the exact next operation sequence.
    pub(crate) const fn operation_sequence(self) -> u64 {
        self.operation_sequence
    }

    /// Returns the closed lifecycle action.
    pub(crate) const fn action(self) -> NetworkNamespaceLifecycleActionV1 {
        self.action
    }

    /// Returns the exact protected authority fence.
    pub(crate) const fn fence(self) -> NetworkLifecycleFenceV1 {
        self.fence
    }

    /// Returns the exact kernel object identity.
    pub(crate) const fn kernel(self) -> NetworkLifecycleKernelIdentityV1 {
        self.kernel
    }

    /// Returns the canonical intent commitment.
    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Carries an opaque protected-current observation required at an effect edge.
///
/// This dormant module deliberately defines no constructor. A future protected
/// adapter must mint it from fresh journal, session, lease, clock, namespace,
/// and kernel observations rather than from request bytes.
#[derive(Debug)]
pub(crate) struct ProtectedNetworkLifecycleCurrentV1 {
    intent_digest: ObjectDigest,
    durable_reducer_digest: ObjectDigest,
    fence_digest: ObjectDigest,
    kernel_digest: ObjectDigest,
    observed_boottime_nanoseconds: u64,
    observation_ordinal: u64,
    residual: NetworkLifecycleResidualV1,
}

/// Classifies exact presence of one cleanup object class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum NetworkLifecycleResidualPresenceV1 {
    /// The complete exact object class remains present.
    Present = 0,
    /// No object in the class remains present.
    Absent = 1,
    /// A nonempty strict subset remains and requires compensation.
    Partial = 2,
}

/// Classifies the exact retained lease-gate state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkLifecycleGateResidualV1 {
    /// The exact admitted lease tuple is installed.
    Armed {
        /// Installed ownership-lease digest.
        lease_digest: ObjectDigest,
        /// Installed lease generation.
        lease_generation: u64,
        /// Installed exclusive fail-stop deadline.
        fail_stop_boottime_nanoseconds: u64,
    },
    /// The exact retained objects enforce default drop.
    DefaultDrop,
    /// No gate remains because its object class was removed.
    Absent,
    /// Gate attachment is incomplete or internally inconsistent.
    Partial,
}

/// Persists broker ownership of namespace-pin teardown during Destroy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkNamespacePinTeardownPhaseV1 {
    /// The broker-owned pin is retained and no teardown was authorized.
    Retained,
    /// Protected broker evidence authorizes teardown of this exact pin.
    BrokerAuthorized(ObjectDigest),
    /// The exact authorized teardown attempt may have run.
    EffectUnknown(ObjectDigest),
    /// Protected absence evidence proves the broker-owned pin is gone.
    ObservedAbsent(ObjectDigest),
}

/// Distinguishes isolated loopback from the complete veth topology residual.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkLifecycleTopologyResidualV1 {
    /// Only exact loopback state exists in the namespace.
    Isolated {
        /// Exact loopback object presence.
        loopback: NetworkLifecycleResidualPresenceV1,
    },
    /// Exact loopback, peer links, and configured L3 inventories are tracked.
    Veth {
        /// Exact loopback object presence.
        loopback: NetworkLifecycleResidualPresenceV1,
        /// Exact host peer presence.
        host_peer: NetworkLifecycleResidualPresenceV1,
        /// Exact sandbox peer presence.
        sandbox_peer: NetworkLifecycleResidualPresenceV1,
        /// Exact address-pair inventory disposition.
        addresses: NetworkLifecycleResidualPresenceV1,
        /// Exact route inventory disposition.
        routes: NetworkLifecycleResidualPresenceV1,
        /// Exact permanent-neighbor inventory disposition.
        neighbors: NetworkLifecycleResidualPresenceV1,
    },
}

/// Records exact operational state of every present action-owned link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum NetworkLifecycleLinkOperationalV1 {
    /// All exact present links are down.
    Down = 0,
    /// All exact present links are up.
    Up = 1,
    /// No action-owned link remains.
    Absent = 2,
    /// Link operational state is mixed or incomplete.
    Partial = 3,
}

/// Records exact one-for-one progress through the worker execution order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum NetworkLifecycleActionProgressV1 {
    /// No operation step has been observed for this intent.
    Initial = 0,
    /// Exact links were observed down.
    LinksDown = 1,
    /// The action-specific lease gate update was observed.
    GateProgrammed = 2,
    /// Exact address pairs were observed configured.
    AddressesConfigured = 3,
    /// Exact routes were observed configured.
    RoutesConfigured = 4,
    /// Exact permanent neighbors were observed configured.
    NeighborsConfigured = 5,
    /// The complete exact plan was reverified.
    PlanVerified = 6,
    /// Exact links were observed raised.
    LinksRaised = 7,
    /// Exact tc attachments were observed absent.
    TcDetached = 8,
    /// Exact bpffs pins were observed absent.
    BpffsRemoved = 9,
    /// Exact links were observed absent.
    LinksRemoved = 10,
    /// Broker namespace-pin teardown authority was observed.
    PinAuthorized = 11,
    /// Broker namespace-pin absence was observed.
    PinRemoved = 12,
}

/// Names one closed, individually recoverable Network effect step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum NetworkLifecycleEffectStepV1 {
    /// Confirms exact links remain down before activation or containment.
    EnsureLinksDown = 0,
    /// Programs the exact admitted lease tuple.
    ProgramLeaseGate = 1,
    /// Configures the exact plan-derived address pairs.
    ConfigureExactAddressPairs = 2,
    /// Configures the exact plan-derived routes.
    ConfigureExactRoutes = 3,
    /// Configures the exact permanent-neighbor inventory.
    ConfigureExactPermanentNeighbors = 4,
    /// Verifies the complete exact plan before changing link state.
    VerifyExactPlanConfiguration = 5,
    /// Raises exact veth links only after verification.
    RaiseLinks = 6,
    /// Lowers exact veth links before containment or destruction.
    LowerLinks = 7,
    /// Restores default drop before destructive cleanup.
    ProgramDefaultDrop = 8,
    /// Detaches every exact tc-BPF gate attachment.
    DetachTcGate = 9,
    /// Removes the exact retained bpffs pins.
    RemoveBpffsPins = 10,
    /// Removes both exact retained link identities.
    RemoveLinks = 11,
    /// Requests broker authority to remove its namespace pin.
    AuthorizeNamespacePinTeardown = 12,
    /// Removes only the broker-authorized exact namespace pin.
    RemoveNamespacePin = 13,
}

/// Carries a stable protected residual inventory after one step or crash.
///
/// No constructor is supplied. A future protected observer must bind the exact
/// catalog row and all four kernel object classes in two equal observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkLifecycleResidualV1 {
    intent_digest: ObjectDigest,
    assignment: BrokerAssignment,
    kernel_digest: ObjectDigest,
    state: NetworkNamespaceObservedStateV1,
    resource_digest: ObjectDigest,
    catalog_digest: ObjectDigest,
    currentness_digest: ObjectDigest,
    namespace: NetworkLifecycleResidualPresenceV1,
    links: NetworkLifecycleResidualPresenceV1,
    topology: NetworkLifecycleTopologyResidualV1,
    link_operational: NetworkLifecycleLinkOperationalV1,
    action_progress: NetworkLifecycleActionProgressV1,
    bpffs: NetworkLifecycleResidualPresenceV1,
    tc: NetworkLifecycleResidualPresenceV1,
    gate: NetworkLifecycleGateResidualV1,
    pin_teardown: NetworkNamespacePinTeardownPhaseV1,
    observed_boottime_nanoseconds: u64,
    observation_ordinal: u64,
    first_snapshot_digest: ObjectDigest,
    second_snapshot_digest: ObjectDigest,
    digest: ObjectDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NetworkLifecycleStepAttemptV1 {
    step: NetworkLifecycleEffectStepV1,
    attempt_ordinal: u64,
    predecessor_residual: NetworkLifecycleResidualV1,
    released_boottime_nanoseconds: Option<u64>,
    released_observation_ordinal: Option<u64>,
    evidence_digest: Option<ObjectDigest>,
    digest: ObjectDigest,
}

/// Carries a move-only commitment awaiting durable effect-unknown readback.
#[derive(Debug)]
pub(crate) struct NetworkLifecycleEffectPreflightV1 {
    intent_digest: ObjectDigest,
    step_attempt_digest: ObjectDigest,
    recovery_digest: ObjectDigest,
}

/// Carries the durable worker-plan watermark awaiting protected readback.
#[derive(Debug)]
pub(crate) struct NetworkLifecycleReleasePreflightV1 {
    intent_digest: ObjectDigest,
    step_attempt_digest: ObjectDigest,
    release_digest: ObjectDigest,
    recovery_digest: ObjectDigest,
}

/// Carries the only effect plan emitted by this reducer.
#[derive(Debug)]
pub(crate) struct NetworkLifecycleEffectPlanV1 {
    intent: NetworkLifecycleIntentV1,
    step: NetworkLifecycleEffectStepV1,
    step_attempt_digest: ObjectDigest,
    released_boottime_nanoseconds: u64,
    released_observation_ordinal: u64,
    release_digest: ObjectDigest,
    recovery_digest: ObjectDigest,
}

impl NetworkLifecycleEffectPlanV1 {
    /// Returns the exact frozen intent; it carries no descriptor or syscall.
    pub(crate) const fn intent(&self) -> NetworkLifecycleIntentV1 {
        self.intent
    }

    /// Returns the sole observation-selected effect step.
    pub(crate) const fn step(&self) -> NetworkLifecycleEffectStepV1 {
        self.step
    }

    /// Returns the exact plan-release watermark the observation must echo.
    pub(crate) const fn release_digest(&self) -> ObjectDigest {
        self.release_digest
    }

    /// Returns the durable ambiguous-state commitment that must precede use.
    pub(crate) const fn recovery_digest(&self) -> ObjectDigest {
        self.recovery_digest
    }
}

/// Classifies the complete post-effect kernel observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkLifecycleObservationDispositionV1 {
    /// The namespace identity remains; the residual closes subordinate state.
    Present(NetworkLifecycleKernelIdentityV1),
    /// Namespace, link, bpffs pins, and tc policy were all observed absent.
    Destroyed(NetworkLifecycleCleanupObservationV1),
}

/// Binds independent absence evidence for every Network kernel object class.
///
/// This source partition supplies no constructor. The future protected kernel
/// observer must mint all four evidence commitments from one stable inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkLifecycleCleanupObservationV1 {
    namespace_absence_digest: ObjectDigest,
    link_absence_digest: ObjectDigest,
    bpffs_absence_digest: ObjectDigest,
    tc_absence_digest: ObjectDigest,
    digest: ObjectDigest,
}

/// Carries a stable protected post-effect observation for one frozen intent.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProtectedNetworkLifecycleObservationV1 {
    intent_digest: ObjectDigest,
    fence_digest: ObjectDigest,
    prior_resource_digest: ObjectDigest,
    result_resource_digest: ObjectDigest,
    observed_state: NetworkNamespaceObservedStateV1,
    disposition: NetworkLifecycleObservationDispositionV1,
    observed_boottime_nanoseconds: u64,
    observation_ordinal: u64,
    step_attempt_digest: ObjectDigest,
    release_digest: ObjectDigest,
    step_evidence_digest: ObjectDigest,
    residual: NetworkLifecycleResidualV1,
    first_snapshot_digest: ObjectDigest,
    second_snapshot_digest: ObjectDigest,
    digest: ObjectDigest,
}

/// Reports the durable phase that restart recovery must preserve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkLifecycleReducerPhaseV1 {
    /// The intent is frozen but no effect authorization was released.
    Prepared,
    /// The pending attempt is durable, but no plan-release watermark exists.
    EffectUnknown,
    /// The exact plan-release watermark is durable and may have been exposed.
    ReleaseFrozen,
    /// A complete exact observation is frozen pending durable receipt commit.
    Observed,
}

#[derive(Clone, Copy, Debug)]
struct PendingNetworkLifecycleV1 {
    intent: NetworkLifecycleIntentV1,
    phase: NetworkLifecycleReducerPhaseV1,
    observation_digest: Option<ObjectDigest>,
    result_resource_digest: Option<ObjectDigest>,
    effect_applied: Option<bool>,
    latest_residual_digest: Option<ObjectDigest>,
    latest_residual: Option<NetworkLifecycleResidualV1>,
    latest_disposition: Option<NetworkLifecycleObservationDispositionV1>,
    next_attempt_ordinal: u64,
    step_attempt: Option<NetworkLifecycleStepAttemptV1>,
    any_effect_applied: bool,
    step_evidence_count: u64,
    step_evidence_anchor: Option<ObjectDigest>,
    prior_step_evidence_anchor: Option<ObjectDigest>,
    last_completed_attempt: Option<NetworkLifecycleStepAttemptV1>,
    last_completed_residual_digest: Option<ObjectDigest>,
    last_observation: Option<ProtectedNetworkLifecycleObservationV1>,
    pin_teardown_phase: NetworkNamespacePinTeardownPhaseV1,
    last_released_boottime_nanoseconds: Option<u64>,
    last_released_observation_ordinal: Option<u64>,
    last_observation_ordinal: Option<u64>,
    observed_residual: Option<NetworkLifecycleResidualV1>,
    observed_disposition: Option<NetworkLifecycleObservationDispositionV1>,
    observed_release_digest: Option<ObjectDigest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompactedNetworkLifecycleReceiptV1 {
    request_id: [u8; 16],
    operation_sequence: u64,
    intent_digest: ObjectDigest,
    receipt_digest: ObjectDigest,
    result_resource_digest: ObjectDigest,
    result_state: NetworkNamespaceObservedStateV1,
    kernel_digest: ObjectDigest,
}

/// Stores one byte-exact idempotent lifecycle result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NetworkLifecycleReceiptV1 {
    request_id: [u8; 16],
    operation_sequence: u64,
    action: NetworkNamespaceLifecycleActionV1,
    assignment: BrokerAssignment,
    intent_digest: ObjectDigest,
    prior_resource_digest: ObjectDigest,
    result_resource_digest: ObjectDigest,
    prior_state: NetworkNamespaceObservedStateV1,
    result_state: NetworkNamespaceObservedStateV1,
    observation_digest: ObjectDigest,
    kernel_digest: ObjectDigest,
    effect_applied: bool,
    step_evidence_count: u64,
    step_evidence_anchor: ObjectDigest,
    last_released_boottime_nanoseconds: Option<u64>,
    last_released_observation_ordinal: Option<u64>,
    last_observation_ordinal: u64,
    namespace_pin_teardown_digest: Option<ObjectDigest>,
    terminal_destroyed: bool,
    digest: ObjectDigest,
}

impl NetworkLifecycleReceiptV1 {
    /// Returns the exact idempotency request identity.
    pub(crate) const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the immutable intent commitment.
    pub(crate) const fn intent_digest(self) -> ObjectDigest {
        self.intent_digest
    }

    /// Returns the exact post-effect resource commitment.
    pub(crate) const fn result_resource_digest(self) -> ObjectDigest {
        self.result_resource_digest
    }

    /// Reports whether stable observation proved the requested effect applied.
    pub(crate) const fn effect_applied(self) -> bool {
        self.effect_applied
    }

    /// Reports whether this receipt irreversibly retires the handle.
    pub(crate) const fn terminal_destroyed(self) -> bool {
        self.terminal_destroyed
    }

    /// Returns the canonical receipt commitment.
    pub(crate) const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Reports begin or replay without silently replacing an unresolved attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkLifecycleBeginOutcomeV1 {
    /// A new intent was frozen in Prepared state.
    Prepared,
    /// The exact unresolved intent already exists at this phase.
    PendingReplay(NetworkLifecycleReducerPhaseV1),
    /// The exact request already committed and returns its stable receipt.
    CommittedReplay(NetworkLifecycleReceiptV1),
    /// The exact request is below the compaction floor and returns its digest.
    CompactedReplay {
        /// Original operation sequence.
        operation_sequence: u64,
        /// Exact committed result resource.
        result_resource_digest: ObjectDigest,
        /// Original full receipt commitment.
        receipt_digest: ObjectDigest,
    },
}

/// Reports whether exact observation proved no effect or froze an applied one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkLifecycleObserveOutcomeV1 {
    /// Stable protected observation proves the prior state is wholly unchanged.
    FrozenNotApplied,
    /// Stable protected observation proves the requested state was applied.
    FrozenApplied,
    /// A partial residual authorizes only this next observed compensation step.
    Continue(NetworkLifecycleEffectStepV1),
}

/// Directs restart handling without fabricating execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkLifecycleRecoveryDispositionV1 {
    /// Nothing is pending.
    Idle,
    /// Prepared may be reconsidered only with a new protected-current token.
    RevalidatePrepared(ObjectDigest),
    /// An effect may have run and only exact observation is permitted.
    ObserveOnly(ObjectDigest),
    /// Observation is complete and its exact receipt may be durably committed.
    CommitObserved(ObjectDigest),
    /// Destroy is terminal; no operation may recreate this handle.
    TerminalDestroyed(NetworkLifecycleReceiptV1),
}

/// Reduces one handle's lifecycle with bounded single-attempt crash state.
#[derive(Debug)]
pub(crate) struct NetworkLifecycleReducerV1 {
    assignment: BrokerAssignment,
    namespace: NetworkNamespaceIdentityV1,
    kernel: NetworkLifecycleKernelIdentityV1,
    state: NetworkNamespaceObservedStateV1,
    resource_digest: ObjectDigest,
    highest_sequence: u64,
    receipt_floor_sequence: u64,
    receipt_anchor_digest: Option<ObjectDigest>,
    pending: Option<PendingNetworkLifecycleV1>,
    compacted_receipt_index: Vec<CompactedNetworkLifecycleReceiptV1>,
    receipts: Vec<NetworkLifecycleReceiptV1>,
    terminal_destroyed: bool,
    poisoned: bool,
}

/// Owns one bounded canonical reducer snapshot for protected persistence.
#[derive(Clone, Debug)]
pub(crate) struct NetworkLifecycleRecoverySnapshotV1 {
    assignment: BrokerAssignment,
    namespace: NetworkNamespaceIdentityV1,
    kernel: NetworkLifecycleKernelIdentityV1,
    state: NetworkNamespaceObservedStateV1,
    resource_digest: ObjectDigest,
    highest_sequence: u64,
    receipt_floor_sequence: u64,
    receipt_anchor_digest: Option<ObjectDigest>,
    pending: Option<PendingNetworkLifecycleV1>,
    compacted_receipt_index: Vec<CompactedNetworkLifecycleReceiptV1>,
    receipts: Vec<NetworkLifecycleReceiptV1>,
    terminal_destroyed: bool,
    poisoned: bool,
    digest: ObjectDigest,
}

/// Authorizes one exact protected receipt-prefix compaction.
///
/// No constructor is supplied; a protected journal adapter must bind the
/// current snapshot, selected floor, derived anchor, and retained index.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProtectedNetworkLifecycleCompactionV1 {
    snapshot_digest: ObjectDigest,
    through_sequence: u64,
    anchor_digest: ObjectDigest,
    replay_index_digest: ObjectDigest,
}

/// Owns a bounded checkpoint envelope awaiting protected durable storage.
///
/// This in-memory value is not evidence of persistence. A future protected
/// adapter must durably write and read back `checkpoint` before recovery.
#[derive(Clone, Debug)]
pub(crate) struct NetworkLifecycleRecoveryStoreV1 {
    checkpoint: Vec<u8>,
}

impl NetworkLifecycleRecoveryStoreV1 {
    /// Seals one typed snapshot into its canonical bounded checkpoint envelope.
    pub(crate) fn checkpoint(
        snapshot: NetworkLifecycleRecoverySnapshotV1,
    ) -> Result<Self, NetworkLifecycleReducerError> {
        NetworkLifecycleReducerV1::recover(snapshot.clone())?;
        let payload = codec::encode_snapshot(&snapshot)?;
        let decoded = codec::decode_snapshot(&payload)?;
        if decoded.digest != snapshot.digest || codec::encode_snapshot(&decoded)? != payload {
            return Err(NetworkLifecycleReducerError::ObservationMismatch);
        }
        let checkpoint = encode_recovery_checkpoint(&snapshot, &payload)?;
        Ok(Self { checkpoint })
    }

    /// Validates and owns canonical checkpoint bytes read from protected storage.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes exceed bounds, are noncanonical, or do
    /// not reconstruct one internally consistent reducer snapshot.
    pub(crate) fn from_checkpoint_bytes(
        checkpoint: Vec<u8>,
    ) -> Result<Self, NetworkLifecycleReducerError> {
        let store = Self { checkpoint };
        store.clone().recover()?;
        Ok(store)
    }

    /// Borrows the exact canonical bytes that a protected adapter must persist.
    pub(crate) fn checkpoint_bytes(&self) -> &[u8] {
        &self.checkpoint
    }

    /// Decodes and verifies the canonical envelope before returning the snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the envelope or payload is noncanonical or its
    /// typed reducer state fails recovery validation.
    pub(crate) fn recover(
        self,
    ) -> Result<NetworkLifecycleRecoverySnapshotV1, NetworkLifecycleReducerError> {
        let payload = recovery_checkpoint_payload(&self.checkpoint)?;
        let snapshot = codec::decode_snapshot(payload)?;
        validate_recovery_checkpoint(&self.checkpoint, &snapshot, payload)?;
        if codec::encode_snapshot(&snapshot)? != payload {
            return Err(NetworkLifecycleReducerError::ObservationMismatch);
        }
        NetworkLifecycleReducerV1::recover(snapshot.clone())?;
        Ok(snapshot)
    }
}

impl NetworkLifecycleReducerV1 {
    /// Constructs a reducer from one exact protected catalog head.
    pub(crate) fn from_catalog_head(
        assignment: BrokerAssignment,
        namespace: NetworkNamespaceIdentityV1,
        kernel: NetworkLifecycleKernelIdentityV1,
        state: NetworkNamespaceObservedStateV1,
        resource_digest: ObjectDigest,
        highest_sequence: u64,
        receipt_floor_sequence: u64,
        receipt_anchor_digest: Option<ObjectDigest>,
        compacted_receipt_index: Vec<CompactedNetworkLifecycleReceiptV1>,
        receipts: Vec<NetworkLifecycleReceiptV1>,
    ) -> Result<Self, NetworkLifecycleReducerError> {
        let last_receipt = receipts.last().copied();
        if kernel.namespace() != namespace
            || resource_digest.as_bytes() == &[0; 32]
            || receipts.len() > MAXIMUM_RETAINED_RECEIPTS
            || compacted_receipt_index.len() > MAXIMUM_COMPACTED_RECEIPTS
            || compacted_receipt_index.len() as u64 != receipt_floor_sequence
            || receipt_anchor_digest.is_some_and(|anchor| {
                anchor != receipt_compacted_anchor(&compacted_receipt_index, &[])
            })
            || receipt_floor_sequence > highest_sequence
            || (receipt_floor_sequence == 0) != receipt_anchor_digest.is_none()
            || (receipts.is_empty() && highest_sequence != receipt_floor_sequence)
            || (receipt_floor_sequence != 0 && receipts.is_empty())
            || receipts.iter().enumerate().any(|(index, receipt)| {
                Some(receipt.operation_sequence)
                    != receipt_floor_sequence
                        .checked_add(index as u64)
                        .and_then(|value| value.checked_add(1))
                    || receipt.request_id == [0; 16]
                    || receipt.assignment != assignment
                    || receipt.kernel_digest != kernel.digest()
                    || [
                        receipt.intent_digest,
                        receipt.prior_resource_digest,
                        receipt.result_resource_digest,
                        receipt.observation_digest,
                        receipt.kernel_digest,
                        receipt.step_evidence_anchor,
                        receipt.digest,
                    ]
                    .iter()
                    .any(|digest| digest.as_bytes() == &[0; 32])
                    || receipt.terminal_destroyed
                        != (receipt.action == NetworkNamespaceLifecycleActionV1::Destroy
                            && receipt.effect_applied)
                    || receipt.step_evidence_count == 0
                    || receipt.last_observation_ordinal == 0
                    || receipt.last_released_boottime_nanoseconds.is_some()
                        != receipt.last_released_observation_ordinal.is_some()
                    || receipt
                        .last_released_observation_ordinal
                        .is_some_and(|ordinal| receipt.last_observation_ordinal <= ordinal)
                    || receipt.terminal_destroyed != receipt.namespace_pin_teardown_digest.is_some()
                    || receipt
                        .namespace_pin_teardown_digest
                        .is_some_and(|digest| digest.as_bytes() == &[0; 32])
                    || !valid_receipt_state_transition(*receipt)
                    || receipt.terminal_destroyed && index + 1 != receipts.len()
                    || index > 0
                        && (receipt.prior_resource_digest
                            != receipts[index - 1].result_resource_digest
                            || receipt.prior_state != receipts[index - 1].result_state)
            })
            || compacted_receipt_index
                .iter()
                .enumerate()
                .any(|(index, receipt)| {
                    receipt.operation_sequence != (index as u64) + 1
                        || receipt.request_id == [0; 16]
                        || receipt.kernel_digest != kernel.digest()
                        || [
                            receipt.intent_digest,
                            receipt.result_resource_digest,
                            receipt.kernel_digest,
                            receipt.receipt_digest,
                        ]
                        .iter()
                        .any(|digest| digest.as_bytes() == &[0; 32])
                        || receipt.result_state.kind()
                            == NetworkNamespaceObservedStateKindV1::Absent
                        || compacted_receipt_index[..index]
                            .iter()
                            .any(|prior| prior.request_id == receipt.request_id)
                })
            || compacted_receipt_index.last().is_some_and(|receipt| {
                receipt.operation_sequence != receipt_floor_sequence
                    || receipts.first().is_some_and(|retained| {
                        retained.prior_resource_digest != receipt.result_resource_digest
                            || retained.prior_state != receipt.result_state
                    })
            })
            || receipts.iter().any(|receipt| {
                compacted_receipt_index
                    .iter()
                    .any(|prior| prior.request_id == receipt.request_id)
            })
            || last_receipt.is_some_and(|value| value.operation_sequence != highest_sequence)
            || last_receipt.is_some_and(|value| {
                value.result_resource_digest() != resource_digest
                    || value.result_state != state
                    || value.kernel_digest != kernel.digest()
            })
            || receipts.iter().enumerate().any(|(index, receipt)| {
                receipts[..index]
                    .iter()
                    .any(|prior| prior.request_id == receipt.request_id)
                    || receipt.digest != receipt_integrity_digest(*receipt)
            })
        {
            return Err(NetworkLifecycleReducerError::Unspecified);
        }
        let terminal_destroyed =
            last_receipt.is_some_and(NetworkLifecycleReceiptV1::terminal_destroyed);
        if terminal_destroyed && state.kind() != NetworkNamespaceObservedStateKindV1::Absent {
            return Err(NetworkLifecycleReducerError::InvalidTransition);
        }
        Ok(Self {
            assignment,
            namespace,
            kernel,
            state,
            resource_digest,
            highest_sequence,
            receipt_floor_sequence,
            receipt_anchor_digest,
            pending: None,
            compacted_receipt_index,
            receipts,
            terminal_destroyed,
            poisoned: false,
        })
    }

    /// Recovers one exact bounded snapshot without creating effect authority.
    pub(crate) fn recover(
        snapshot: NetworkLifecycleRecoverySnapshotV1,
    ) -> Result<Self, NetworkLifecycleReducerError> {
        let expected_digest = reducer_snapshot_digest(
            snapshot.assignment,
            snapshot.namespace,
            snapshot.kernel.digest(),
            snapshot.state,
            snapshot.resource_digest,
            snapshot.highest_sequence,
            snapshot.receipt_floor_sequence,
            snapshot.receipt_anchor_digest,
            snapshot.pending.map(pending_digest),
            &snapshot.compacted_receipt_index,
            &snapshot.receipts,
            snapshot.terminal_destroyed,
            snapshot.poisoned,
        );
        if snapshot.digest != expected_digest
            || snapshot.terminal_destroyed && snapshot.pending.is_some()
            || snapshot.poisoned && snapshot.pending.is_none()
        {
            return Err(NetworkLifecycleReducerError::ObservationMismatch);
        }
        let mut reducer = Self::from_catalog_head(
            snapshot.assignment,
            snapshot.namespace,
            snapshot.kernel,
            snapshot.state,
            snapshot.resource_digest,
            snapshot.highest_sequence,
            snapshot.receipt_floor_sequence,
            snapshot.receipt_anchor_digest,
            snapshot.compacted_receipt_index,
            snapshot.receipts,
        )?;
        if reducer.terminal_destroyed != snapshot.terminal_destroyed {
            return Err(NetworkLifecycleReducerError::InvalidTransition);
        }
        reducer.poisoned = snapshot.poisoned;
        if let Some(pending) = snapshot.pending {
            let expected_sequence = reducer
                .highest_sequence
                .checked_add(1)
                .ok_or(NetworkLifecycleReducerError::SequenceExhausted)?;
            let observation_shape_valid = match pending.phase {
                NetworkLifecycleReducerPhaseV1::Prepared => {
                    pending.observation_digest.is_none()
                        && pending.result_resource_digest.is_none()
                        && pending.effect_applied.is_none()
                        && pending.step_attempt.is_none()
                        && pending.observed_residual.is_none()
                        && pending.observed_disposition.is_none()
                        && pending.observed_release_digest.is_none()
                }
                NetworkLifecycleReducerPhaseV1::EffectUnknown => {
                    pending.observation_digest.is_none()
                        && pending.result_resource_digest.is_none()
                        && pending.effect_applied.is_none()
                        && pending.step_attempt.is_some_and(|attempt| {
                            valid_step_attempt(attempt)
                                && attempt.released_observation_ordinal.is_none()
                        })
                        && pending.observed_residual.is_none()
                        && pending.observed_disposition.is_none()
                        && pending.observed_release_digest.is_none()
                }
                NetworkLifecycleReducerPhaseV1::ReleaseFrozen => {
                    pending.observation_digest.is_none()
                        && pending.result_resource_digest.is_none()
                        && pending.effect_applied.is_none()
                        && pending.step_attempt.is_some_and(|attempt| {
                            valid_step_attempt(attempt)
                                && attempt.released_observation_ordinal.is_some()
                                && attempt.evidence_digest.is_none()
                        })
                        && pending.observed_residual.is_none()
                        && pending.observed_disposition.is_none()
                        && pending.observed_release_digest.is_none()
                }
                NetworkLifecycleReducerPhaseV1::Observed => {
                    pending.observation_digest.is_some()
                        && pending.result_resource_digest.is_some()
                        && pending.effect_applied.is_some()
                        && pending.step_attempt.is_some_and(|attempt| {
                            valid_step_attempt(attempt)
                                && attempt.evidence_digest.is_some()
                                && attempt.released_observation_ordinal.is_some()
                        })
                        && pending.observed_residual.is_some()
                        && pending.observed_disposition.is_some()
                        && pending.observed_release_digest.is_some()
                }
            };
            if pending.intent.operation_sequence() != expected_sequence
                || pending.intent.kernel() != reducer.kernel
                || pending.intent.fence().assignment() != reducer.assignment
                || pending.intent.prior_resource_digest != reducer.resource_digest
                || pending.intent.prior_state != reducer.state
                || !observation_shape_valid
                || pending.next_attempt_ordinal == 0
                || pending.next_attempt_ordinal > MAXIMUM_EFFECT_ATTEMPTS.saturating_add(1)
                || pending.next_attempt_ordinal > MAXIMUM_EFFECT_ATTEMPTS
                    && pending.phase != NetworkLifecycleReducerPhaseV1::Prepared
                || match pending.phase {
                    NetworkLifecycleReducerPhaseV1::Observed => {
                        pending.step_evidence_count != pending.next_attempt_ordinal
                    }
                    _ => {
                        pending.step_evidence_count.checked_add(1)
                            != Some(pending.next_attempt_ordinal)
                    }
                }
                || (pending.step_evidence_count == 0) != pending.step_evidence_anchor.is_none()
                || (pending.step_evidence_count == 0) != pending.last_completed_attempt.is_none()
                || (pending.step_evidence_count == 0)
                    != pending.last_completed_residual_digest.is_none()
                || (pending.step_evidence_count == 0) != pending.last_observation.is_none()
                || (pending.step_evidence_count > 1) != pending.prior_step_evidence_anchor.is_some()
                || (pending.last_released_boottime_nanoseconds.is_some()
                    != pending.last_released_observation_ordinal.is_some())
                || pending.last_observation_ordinal.is_some() != (pending.step_evidence_count != 0)
                || pending
                    .step_attempt
                    .is_some_and(|attempt| attempt.attempt_ordinal != pending.next_attempt_ordinal)
                || pending.step_attempt.is_some_and(|attempt| {
                    attempt.released_boottime_nanoseconds.is_some()
                        && (attempt.released_boottime_nanoseconds
                            != pending.last_released_boottime_nanoseconds
                            || attempt.released_observation_ordinal
                                != pending.last_released_observation_ordinal)
                })
                || !valid_recovered_pending(pending)
            {
                return Err(NetworkLifecycleReducerError::InvalidTransition);
            }
            reducer.pending = Some(pending);
        }
        Ok(reducer)
    }

    /// Freezes one immutable intent before any effect plan can be requested.
    pub(crate) fn begin(
        &mut self,
        intent: NetworkLifecycleIntentV1,
    ) -> Result<NetworkLifecycleBeginOutcomeV1, NetworkLifecycleReducerError> {
        self.ensure_healthy()?;
        if let Some(receipt) = self
            .receipts
            .iter()
            .copied()
            .find(|receipt| receipt.request_id() == intent.request_id())
        {
            return if receipt.intent_digest() == intent.digest() {
                Ok(NetworkLifecycleBeginOutcomeV1::CommittedReplay(receipt))
            } else {
                Err(NetworkLifecycleReducerError::Equivocation)
            };
        }
        if let Some(receipt) = self
            .compacted_receipt_index
            .iter()
            .copied()
            .find(|receipt| receipt.request_id == intent.request_id())
        {
            return if receipt.intent_digest == intent.digest() {
                Ok(NetworkLifecycleBeginOutcomeV1::CompactedReplay {
                    operation_sequence: receipt.operation_sequence,
                    result_resource_digest: receipt.result_resource_digest,
                    receipt_digest: receipt.receipt_digest,
                })
            } else {
                Err(NetworkLifecycleReducerError::Equivocation)
            };
        }
        if self.terminal_destroyed {
            return Err(NetworkLifecycleReducerError::TerminalDestroyed);
        }
        if let Some(pending) = &self.pending {
            return if pending.intent.request_id() == intent.request_id()
                && pending.intent.digest() == intent.digest()
            {
                Ok(NetworkLifecycleBeginOutcomeV1::PendingReplay(pending.phase))
            } else if pending.intent.request_id() == intent.request_id() {
                Err(NetworkLifecycleReducerError::Equivocation)
            } else {
                Err(NetworkLifecycleReducerError::Pending)
            };
        }
        let expected_sequence = self
            .highest_sequence
            .checked_add(1)
            .ok_or(NetworkLifecycleReducerError::SequenceExhausted)?;
        if intent.operation_sequence() != expected_sequence
            || intent.kernel() != self.kernel
            || intent.fence().assignment() != self.assignment
            || intent.prior_resource_digest != self.resource_digest
            || intent.prior_state != self.state
        {
            return Err(NetworkLifecycleReducerError::StaleSequence);
        }
        self.pending = Some(PendingNetworkLifecycleV1 {
            intent,
            phase: NetworkLifecycleReducerPhaseV1::Prepared,
            observation_digest: None,
            result_resource_digest: None,
            effect_applied: None,
            latest_residual_digest: None,
            latest_residual: None,
            latest_disposition: None,
            next_attempt_ordinal: 1,
            step_attempt: None,
            any_effect_applied: false,
            step_evidence_count: 0,
            step_evidence_anchor: None,
            prior_step_evidence_anchor: None,
            last_completed_attempt: None,
            last_completed_residual_digest: None,
            last_observation: None,
            pin_teardown_phase: NetworkNamespacePinTeardownPhaseV1::Retained,
            last_released_boottime_nanoseconds: None,
            last_released_observation_ordinal: None,
            last_observation_ordinal: None,
            observed_residual: None,
            observed_disposition: None,
            observed_release_digest: None,
        });
        Ok(NetworkLifecycleBeginOutcomeV1::Prepared)
    }

    /// Marks the effect boundary ambiguous before any effect plan can exist.
    pub(crate) fn prepare_effect(
        &mut self,
        current: ProtectedNetworkLifecycleCurrentV1,
    ) -> Result<NetworkLifecycleEffectPreflightV1, NetworkLifecycleReducerError> {
        self.ensure_healthy()?;
        let expected_reducer_digest = self.snapshot_digest();
        let pending = self
            .pending
            .as_mut()
            .ok_or(NetworkLifecycleReducerError::Pending)?;
        if pending.phase != NetworkLifecycleReducerPhaseV1::Prepared {
            return Err(NetworkLifecycleReducerError::Pending);
        }
        let intent = pending.intent;
        if current.intent_digest != intent.digest()
            || current.durable_reducer_digest != expected_reducer_digest
            || current.fence_digest != intent.fence().digest()
            || current.kernel_digest != intent.kernel().digest()
            || current.observed_boottime_nanoseconds == 0
            || current.observation_ordinal == 0
        {
            return Err(NetworkLifecycleReducerError::CurrentnessMismatch);
        }
        if matches!(
            intent.action(),
            NetworkNamespaceLifecycleActionV1::Arm | NetworkNamespaceLifecycleActionV1::Renew
        ) && current.observed_boottime_nanoseconds
            >= intent.fence().fail_stop_boottime_nanoseconds()
        {
            return Err(NetworkLifecycleReducerError::LeaseMismatch);
        }
        validate_residual(intent, current.residual)?;
        if current.residual.observed_boottime_nanoseconds != current.observed_boottime_nanoseconds
            || current.residual.observation_ordinal != current.observation_ordinal
            || pending.latest_residual_digest.is_none()
                && (current.residual.resource_digest != intent.prior_resource_digest
                    || current.residual.catalog_digest != intent.prior_catalog_digest
                    || current.residual.currentness_digest != intent.fence().currentness_digest()
                    || current.residual.state != intent.prior_state
                    || current.residual.action_progress
                        != NetworkLifecycleActionProgressV1::Initial)
            || pending
                .latest_residual_digest
                .is_some_and(|digest| digest != residual_semantic_digest(current.residual))
            || pending.latest_residual.is_some_and(|residual| {
                residual_semantic_digest(residual) != residual_semantic_digest(current.residual)
                    || current.residual.observation_ordinal <= residual.observation_ordinal
            })
            || !pin_phase_matches_residual(
                pending.pin_teardown_phase,
                current.residual.pin_teardown,
            )
        {
            return Err(NetworkLifecycleReducerError::CurrentnessMismatch);
        }
        let step = next_effect_step(intent, current.residual)?
            .ok_or(NetworkLifecycleReducerError::ObservationMismatch)?;
        if pending.next_attempt_ordinal > MAXIMUM_EFFECT_ATTEMPTS {
            return Err(NetworkLifecycleReducerError::ReceiptHistoryExhausted);
        }
        let mut attempt = NetworkLifecycleStepAttemptV1 {
            step,
            attempt_ordinal: pending.next_attempt_ordinal,
            predecessor_residual: current.residual,
            released_boottime_nanoseconds: None,
            released_observation_ordinal: None,
            evidence_digest: None,
            digest: zero_digest(),
        };
        attempt.digest = step_attempt_digest(attempt);

        pending.phase = NetworkLifecycleReducerPhaseV1::EffectUnknown;
        if step == NetworkLifecycleEffectStepV1::RemoveNamespacePin {
            let NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(authorization) =
                pending.pin_teardown_phase
            else {
                return Err(NetworkLifecycleReducerError::InvalidTransition);
            };
            pending.pin_teardown_phase =
                NetworkNamespacePinTeardownPhaseV1::EffectUnknown(authorization);
        }
        pending.step_attempt = Some(attempt);
        let recovery_digest = reducer_snapshot_digest(
            self.assignment,
            self.namespace,
            self.kernel.digest(),
            self.state,
            self.resource_digest,
            self.highest_sequence,
            self.receipt_floor_sequence,
            self.receipt_anchor_digest,
            Some(pending_digest(*pending)),
            &self.compacted_receipt_index,
            &self.receipts,
            self.terminal_destroyed,
            self.poisoned,
        );
        Ok(NetworkLifecycleEffectPreflightV1 {
            intent_digest: intent.digest(),
            step_attempt_digest: attempt.digest,
            recovery_digest,
        })
    }

    /// Releases a plan only after effect-unknown state has protected readback.
    pub(crate) fn freeze_release(
        &mut self,
        preflight: NetworkLifecycleEffectPreflightV1,
        current: ProtectedNetworkLifecycleCurrentV1,
    ) -> Result<NetworkLifecycleReleasePreflightV1, NetworkLifecycleReducerError> {
        self.ensure_healthy()?;
        let reducer_digest = self.snapshot_digest();
        let (intent, attempt) = {
            let pending = self
                .pending
                .as_mut()
                .ok_or(NetworkLifecycleReducerError::Pending)?;
            let mut attempt = pending
                .step_attempt
                .ok_or(NetworkLifecycleReducerError::Pending)?;
            if pending.phase != NetworkLifecycleReducerPhaseV1::EffectUnknown
                || preflight.intent_digest != pending.intent.digest()
                || preflight.step_attempt_digest != attempt.digest
                || preflight.recovery_digest != reducer_digest
                || current.intent_digest != pending.intent.digest()
                || current.durable_reducer_digest != preflight.recovery_digest
                || current.fence_digest != pending.intent.fence().digest()
                || current.kernel_digest != pending.intent.kernel().digest()
                || current.observed_boottime_nanoseconds == 0
                || current.observation_ordinal <= attempt.predecessor_residual.observation_ordinal
                || current.residual.observation_ordinal != current.observation_ordinal
                || current.residual.observed_boottime_nanoseconds
                    != current.observed_boottime_nanoseconds
                || residual_semantic_digest(current.residual)
                    != residual_semantic_digest(attempt.predecessor_residual)
            {
                return Err(NetworkLifecycleReducerError::CurrentnessMismatch);
            }
            validate_residual(pending.intent, current.residual)?;
            if matches!(
                pending.intent.action(),
                NetworkNamespaceLifecycleActionV1::Arm | NetworkNamespaceLifecycleActionV1::Renew
            ) && current.observed_boottime_nanoseconds
                >= pending.intent.fence().fail_stop_boottime_nanoseconds()
            {
                return Err(NetworkLifecycleReducerError::LeaseMismatch);
            }

            attempt.released_boottime_nanoseconds = Some(current.observed_boottime_nanoseconds);
            attempt.released_observation_ordinal = Some(current.observation_ordinal);
            pending.step_attempt = Some(attempt);
            pending.last_released_boottime_nanoseconds =
                Some(current.observed_boottime_nanoseconds);
            pending.last_released_observation_ordinal = Some(current.observation_ordinal);
            pending.phase = NetworkLifecycleReducerPhaseV1::ReleaseFrozen;
            (pending.intent, attempt)
        };
        let release_digest = plan_release_digest(intent.digest(), attempt.digest);
        let recovery_digest = self.snapshot_digest();

        Ok(NetworkLifecycleReleasePreflightV1 {
            intent_digest: intent.digest(),
            step_attempt_digest: attempt.digest,
            release_digest,
            recovery_digest,
        })
    }

    /// Rolls back an unexposed attempt after fresh exact protected observation.
    pub(crate) fn revalidate_unreleased(
        &mut self,
        current: ProtectedNetworkLifecycleCurrentV1,
    ) -> Result<(), NetworkLifecycleReducerError> {
        self.ensure_healthy()?;
        let durable_digest = self.snapshot_digest();
        let mut pending = self.pending.ok_or(NetworkLifecycleReducerError::Pending)?;
        let attempt = pending
            .step_attempt
            .ok_or(NetworkLifecycleReducerError::Pending)?;
        if pending.phase != NetworkLifecycleReducerPhaseV1::EffectUnknown
            || current.durable_reducer_digest != durable_digest
            || current.intent_digest != pending.intent.digest()
            || current.observation_ordinal <= attempt.predecessor_residual.observation_ordinal
            || current.residual.observation_ordinal != current.observation_ordinal
            || residual_semantic_digest(current.residual)
                != residual_semantic_digest(attempt.predecessor_residual)
        {
            return Err(NetworkLifecycleReducerError::CurrentnessMismatch);
        }
        validate_residual(pending.intent, current.residual)?;
        if let NetworkLifecycleEffectStepV1::RemoveNamespacePin = attempt.step {
            let NetworkNamespacePinTeardownPhaseV1::EffectUnknown(authorization) =
                pending.pin_teardown_phase
            else {
                return Err(NetworkLifecycleReducerError::ObservationMismatch);
            };
            pending.pin_teardown_phase =
                NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(authorization);
        }
        pending.phase = NetworkLifecycleReducerPhaseV1::Prepared;
        pending.step_attempt = None;
        self.pending = Some(pending);
        Ok(())
    }

    /// Exposes one plan only after its exact release watermark has readback.
    pub(crate) fn release_effect(
        &self,
        release: NetworkLifecycleReleasePreflightV1,
        current: ProtectedNetworkLifecycleCurrentV1,
    ) -> Result<NetworkLifecycleEffectPlanV1, NetworkLifecycleReducerError> {
        self.ensure_healthy()?;
        let pending = self.pending.ok_or(NetworkLifecycleReducerError::Pending)?;
        let attempt = pending
            .step_attempt
            .ok_or(NetworkLifecycleReducerError::Pending)?;
        let released_ordinal = attempt
            .released_observation_ordinal
            .ok_or(NetworkLifecycleReducerError::CurrentnessMismatch)?;
        if pending.phase != NetworkLifecycleReducerPhaseV1::ReleaseFrozen
            || release.intent_digest != pending.intent.digest()
            || release.step_attempt_digest != attempt.digest
            || release.release_digest
                != plan_release_digest(pending.intent.digest(), attempt.digest)
            || release.recovery_digest != self.snapshot_digest()
            || current.durable_reducer_digest != release.recovery_digest
            || current.intent_digest != pending.intent.digest()
            || current.fence_digest != pending.intent.fence().digest()
            || current.kernel_digest != pending.intent.kernel().digest()
            || current.observation_ordinal <= released_ordinal
            || current.residual.observation_ordinal != current.observation_ordinal
            || current.residual.observed_boottime_nanoseconds
                != current.observed_boottime_nanoseconds
            || residual_semantic_digest(current.residual)
                != residual_semantic_digest(attempt.predecessor_residual)
        {
            return Err(NetworkLifecycleReducerError::CurrentnessMismatch);
        }
        validate_residual(pending.intent, current.residual)?;
        if matches!(
            pending.intent.action(),
            NetworkNamespaceLifecycleActionV1::Arm | NetworkNamespaceLifecycleActionV1::Renew
        ) && current.observed_boottime_nanoseconds
            >= pending.intent.fence().fail_stop_boottime_nanoseconds()
        {
            return Err(NetworkLifecycleReducerError::LeaseMismatch);
        }

        Ok(NetworkLifecycleEffectPlanV1 {
            intent: pending.intent,
            step: attempt.step,
            step_attempt_digest: attempt.digest,
            released_boottime_nanoseconds: attempt
                .released_boottime_nanoseconds
                .ok_or(NetworkLifecycleReducerError::CurrentnessMismatch)?,
            released_observation_ordinal: released_ordinal,
            release_digest: release.release_digest,
            recovery_digest: release.recovery_digest,
        })
    }

    /// Accepts only a stable protected observation of the ambiguous effect.
    pub(crate) fn observe(
        &mut self,
        observation: ProtectedNetworkLifecycleObservationV1,
    ) -> Result<NetworkLifecycleObserveOutcomeV1, NetworkLifecycleReducerError> {
        self.ensure_healthy()?;
        match self.validate_observation(observation) {
            Ok((pending, outcome)) => {
                self.pending = Some(pending);
                Ok(outcome)
            }
            Err(error @ NetworkLifecycleReducerError::LeaseMismatch) => Err(error),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    fn validate_observation(
        &self,
        observation: ProtectedNetworkLifecycleObservationV1,
    ) -> Result<
        (PendingNetworkLifecycleV1, NetworkLifecycleObserveOutcomeV1),
        NetworkLifecycleReducerError,
    > {
        let mut pending = self.pending.ok_or(NetworkLifecycleReducerError::Pending)?;
        let mut attempt = pending
            .step_attempt
            .ok_or(NetworkLifecycleReducerError::Pending)?;
        if pending.phase != NetworkLifecycleReducerPhaseV1::ReleaseFrozen
            || observation.intent_digest != pending.intent.digest()
            || observation.fence_digest != pending.intent.fence().digest()
            || observation.prior_resource_digest != pending.intent.prior_resource_digest
            || observation.result_resource_digest.as_bytes() == &[0; 32]
            || observation.observed_boottime_nanoseconds == 0
            || observation.observation_ordinal <= attempt.predecessor_residual.observation_ordinal
            || observation.step_attempt_digest != attempt.digest
            || observation.release_digest
                != plan_release_digest(pending.intent.digest(), attempt.digest)
            || observation.step_evidence_digest.as_bytes() == &[0; 32]
            || observation.first_snapshot_digest.as_bytes() == &[0; 32]
            || observation.first_snapshot_digest != observation.second_snapshot_digest
        {
            return Err(NetworkLifecycleReducerError::ObservationMismatch);
        }
        if let (Some(released_boottime), Some(released_ordinal)) = (
            attempt.released_boottime_nanoseconds,
            attempt.released_observation_ordinal,
        ) && (observation.observed_boottime_nanoseconds < released_boottime
            || observation.observation_ordinal <= released_ordinal)
        {
            return Err(NetworkLifecycleReducerError::ObservationMismatch);
        }
        validate_residual(pending.intent, observation.residual)?;
        validate_step_progress(
            attempt.step,
            attempt.predecessor_residual,
            observation.residual,
        )?;
        validate_action_step_result(
            pending.intent,
            attempt.step,
            attempt.predecessor_residual,
            observation.residual,
        )?;
        if observation.residual.observed_boottime_nanoseconds
            != observation.observed_boottime_nanoseconds
            || observation.residual.observation_ordinal != observation.observation_ordinal
            || observation.residual.resource_digest != observation.result_resource_digest
            || observation.residual.state != observation.observed_state
        {
            return Err(NetworkLifecycleReducerError::ObservationMismatch);
        }
        let step_changed =
            residual_effect_changed(attempt.predecessor_residual, observation.residual);
        pending.any_effect_applied |= step_changed;
        attempt.evidence_digest = Some(observation.step_evidence_digest);
        pending.step_attempt = Some(attempt);

        let prior_evidence_anchor = pending.step_evidence_anchor;
        let evidence_record = step_evidence_record_digest(
            pending.step_evidence_count,
            prior_evidence_anchor,
            attempt,
            observation.residual.digest,
            observation.observed_boottime_nanoseconds,
            observation.observation_ordinal,
        );
        pending.step_evidence_count = pending
            .step_evidence_count
            .checked_add(1)
            .ok_or(NetworkLifecycleReducerError::SequenceExhausted)?;
        pending.step_evidence_anchor = Some(evidence_record);
        pending.prior_step_evidence_anchor = prior_evidence_anchor;
        pending.last_completed_attempt = Some(attempt);
        pending.last_completed_residual_digest = Some(observation.residual.digest);
        pending.last_observation_ordinal = Some(observation.observation_ordinal);
        pending.pin_teardown_phase = match attempt.step {
            NetworkLifecycleEffectStepV1::AuthorizeNamespacePinTeardown => {
                match observation.residual.pin_teardown {
                    NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(authorization) => {
                        NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(authorization)
                    }
                    NetworkNamespacePinTeardownPhaseV1::Retained
                        if observation.residual.action_progress
                            == attempt.predecessor_residual.action_progress =>
                    {
                        NetworkNamespacePinTeardownPhaseV1::Retained
                    }
                    _ => return Err(NetworkLifecycleReducerError::ObservationMismatch),
                }
            }
            NetworkLifecycleEffectStepV1::RemoveNamespacePin => {
                let NetworkNamespacePinTeardownPhaseV1::EffectUnknown(expected) =
                    pending.pin_teardown_phase
                else {
                    return Err(NetworkLifecycleReducerError::ObservationMismatch);
                };
                match observation.residual.pin_teardown {
                    NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(observed)
                        if observed == expected =>
                    {
                        NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(observed)
                    }
                    NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(observed)
                        if observed == expected
                            && observation.residual.namespace
                                != NetworkLifecycleResidualPresenceV1::Absent =>
                    {
                        NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(observed)
                    }
                    _ => return Err(NetworkLifecycleReducerError::ObservationMismatch),
                }
            }
            _ => observation.residual.pin_teardown,
        };

        let expected_digest = observation_digest(
            observation.intent_digest,
            observation.fence_digest,
            observation.prior_resource_digest,
            observation.result_resource_digest,
            observation.observed_state,
            observation.disposition,
            observation.observed_boottime_nanoseconds,
            observation.observation_ordinal,
            observation.step_attempt_digest,
            observation.release_digest,
            observation.step_evidence_digest,
            observation.residual.digest,
            observation.first_snapshot_digest,
            observation.second_snapshot_digest,
        );
        if observation.digest != expected_digest {
            return Err(NetworkLifecycleReducerError::ObservationMismatch);
        }
        pending.last_observation = Some(observation);

        if let Some(next_step) = next_effect_step(pending.intent, observation.residual)? {
            if observation.disposition
                != NetworkLifecycleObservationDispositionV1::Present(pending.intent.kernel)
                || observation.residual.namespace != NetworkLifecycleResidualPresenceV1::Present
            {
                return Err(NetworkLifecycleReducerError::ObservationMismatch);
            }
            pending.phase = NetworkLifecycleReducerPhaseV1::Prepared;
            pending.latest_residual_digest = Some(residual_semantic_digest(observation.residual));
            pending.latest_residual = Some(observation.residual);
            pending.latest_disposition = Some(observation.disposition);
            pending.next_attempt_ordinal = pending
                .next_attempt_ordinal
                .checked_add(1)
                .ok_or(NetworkLifecycleReducerError::SequenceExhausted)?;
            pending.step_attempt = None;
            return Ok((
                pending,
                NetworkLifecycleObserveOutcomeV1::Continue(next_step),
            ));
        }

        let applied = pending.any_effect_applied;
        let terminal_shape_valid = match (pending.intent.action(), observation.disposition) {
            (
                NetworkNamespaceLifecycleActionV1::Destroy,
                NetworkLifecycleObservationDispositionV1::Destroyed(cleanup),
            ) if cleanup.has_complete_evidence(pending.intent.kernel().digest())
                && observation.observed_state == pending.intent.desired_state
                && matches!(
                    pending.pin_teardown_phase,
                    NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(digest)
                        if digest.as_bytes() != &[0; 32]
                ) =>
            {
                true
            }
            (
                NetworkNamespaceLifecycleActionV1::Arm
                | NetworkNamespaceLifecycleActionV1::Renew
                | NetworkNamespaceLifecycleActionV1::Disarm,
                NetworkLifecycleObservationDispositionV1::Present(kernel),
            ) if kernel == pending.intent.kernel
                && observation.observed_state == pending.intent.desired_state =>
            {
                applied
            }
            (_, NetworkLifecycleObservationDispositionV1::Present(kernel))
                if kernel == pending.intent.kernel
                    && observation.observed_state == pending.intent.prior_state
                    && observation.result_resource_digest
                        == pending.intent.prior_resource_digest =>
            {
                !applied
            }
            _ => false,
        };
        if !terminal_shape_valid
            || pending.intent.action() == NetworkNamespaceLifecycleActionV1::Destroy && !applied
            || applied && observation.result_resource_digest == pending.intent.prior_resource_digest
        {
            return Err(NetworkLifecycleReducerError::ObservationMismatch);
        }
        if applied
            && matches!(
                pending.intent.action(),
                NetworkNamespaceLifecycleActionV1::Arm | NetworkNamespaceLifecycleActionV1::Renew
            )
            && observation.observed_boottime_nanoseconds
                >= pending.intent.fence().fail_stop_boottime_nanoseconds()
        {
            return Err(NetworkLifecycleReducerError::LeaseMismatch);
        }

        pending.phase = NetworkLifecycleReducerPhaseV1::Observed;
        pending.observation_digest = Some(observation.digest);
        pending.result_resource_digest = Some(observation.result_resource_digest);
        pending.effect_applied = Some(applied);
        pending.observed_residual = Some(observation.residual);
        pending.observed_disposition = Some(observation.disposition);
        pending.observed_release_digest = Some(observation.release_digest);
        if applied {
            Ok((pending, NetworkLifecycleObserveOutcomeV1::FrozenApplied))
        } else {
            Ok((pending, NetworkLifecycleObserveOutcomeV1::FrozenNotApplied))
        }
    }

    /// Commits one exact observation into a stable idempotent receipt.
    pub(crate) fn commit_observed(
        &mut self,
    ) -> Result<NetworkLifecycleReceiptV1, NetworkLifecycleReducerError> {
        self.ensure_healthy()?;
        let pending = self
            .pending
            .take()
            .ok_or(NetworkLifecycleReducerError::Pending)?;
        let Some(observation_digest) = pending.observation_digest else {
            self.pending = Some(pending);
            return Err(NetworkLifecycleReducerError::Pending);
        };
        let Some(result_resource_digest) = pending.result_resource_digest else {
            self.pending = Some(pending);
            return Err(NetworkLifecycleReducerError::Pending);
        };
        let Some(effect_applied) = pending.effect_applied else {
            self.pending = Some(pending);
            return Err(NetworkLifecycleReducerError::Pending);
        };
        if pending.phase != NetworkLifecycleReducerPhaseV1::Observed {
            self.pending = Some(pending);
            return Err(NetworkLifecycleReducerError::Pending);
        }

        let terminal_destroyed =
            effect_applied && pending.intent.action() == NetworkNamespaceLifecycleActionV1::Destroy;
        let step_evidence_anchor = pending
            .step_evidence_anchor
            .ok_or(NetworkLifecycleReducerError::ObservationMismatch)?;
        let last_observation_ordinal = pending
            .last_observation_ordinal
            .ok_or(NetworkLifecycleReducerError::ObservationMismatch)?;
        let namespace_pin_teardown_digest = match pending.pin_teardown_phase {
            NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(value) => Some(value),
            _ if terminal_destroyed => {
                self.pending = Some(pending);
                return Err(NetworkLifecycleReducerError::ObservationMismatch);
            }
            _ => None,
        };
        let kernel_digest = pending.intent.kernel().digest();
        let mut receipt = NetworkLifecycleReceiptV1 {
            request_id: pending.intent.request_id(),
            operation_sequence: pending.intent.operation_sequence(),
            action: pending.intent.action(),
            assignment: self.assignment,
            intent_digest: pending.intent.digest(),
            prior_resource_digest: pending.intent.prior_resource_digest,
            result_resource_digest,
            prior_state: pending.intent.prior_state,
            result_state: if effect_applied {
                pending.intent.desired_state
            } else {
                pending.intent.prior_state
            },
            observation_digest,
            kernel_digest,
            effect_applied,
            step_evidence_count: pending.step_evidence_count,
            step_evidence_anchor,
            last_released_boottime_nanoseconds: pending.last_released_boottime_nanoseconds,
            last_released_observation_ordinal: pending.last_released_observation_ordinal,
            last_observation_ordinal,
            namespace_pin_teardown_digest,
            terminal_destroyed,
            digest: zero_digest(),
        };
        receipt.digest = receipt_integrity_digest(receipt);
        if self.receipts.len() == MAXIMUM_RETAINED_RECEIPTS {
            self.pending = Some(pending);
            return Err(NetworkLifecycleReducerError::ReceiptHistoryExhausted);
        }
        self.highest_sequence = receipt.operation_sequence;
        self.resource_digest = result_resource_digest;
        self.state = receipt.result_state;
        self.receipts.push(receipt);
        self.terminal_destroyed = terminal_destroyed;
        Ok(receipt)
    }

    /// Returns the sole safe restart disposition for the retained phase.
    pub(crate) fn recovery_disposition(
        &self,
    ) -> Result<NetworkLifecycleRecoveryDispositionV1, NetworkLifecycleReducerError> {
        self.ensure_healthy()?;
        if self.terminal_destroyed {
            let receipt = self
                .receipts
                .last()
                .copied()
                .ok_or(NetworkLifecycleReducerError::ObservationMismatch)?;
            return Ok(NetworkLifecycleRecoveryDispositionV1::TerminalDestroyed(
                receipt,
            ));
        }
        let disposition = match &self.pending {
            None => NetworkLifecycleRecoveryDispositionV1::Idle,
            Some(pending) => match pending.phase {
                NetworkLifecycleReducerPhaseV1::Prepared => {
                    NetworkLifecycleRecoveryDispositionV1::RevalidatePrepared(
                        pending.intent.digest(),
                    )
                }
                NetworkLifecycleReducerPhaseV1::EffectUnknown => {
                    NetworkLifecycleRecoveryDispositionV1::RevalidatePrepared(
                        pending.intent.digest(),
                    )
                }
                NetworkLifecycleReducerPhaseV1::ReleaseFrozen => {
                    NetworkLifecycleRecoveryDispositionV1::ObserveOnly(pending.intent.digest())
                }
                NetworkLifecycleReducerPhaseV1::Observed => {
                    let observation_digest = pending
                        .observation_digest
                        .ok_or(NetworkLifecycleReducerError::ObservationMismatch)?;
                    NetworkLifecycleRecoveryDispositionV1::CommitObserved(observation_digest)
                }
            },
        };
        Ok(disposition)
    }

    /// Returns the canonical commitment to the entire bounded recovery state.
    pub(crate) fn snapshot_digest(&self) -> ObjectDigest {
        reducer_snapshot_digest(
            self.assignment,
            self.namespace,
            self.kernel.digest(),
            self.state,
            self.resource_digest,
            self.highest_sequence,
            self.receipt_floor_sequence,
            self.receipt_anchor_digest,
            self.pending.as_ref().copied().map(pending_digest),
            &self.compacted_receipt_index,
            &self.receipts,
            self.terminal_destroyed,
            self.poisoned,
        )
    }

    /// Freezes the complete bounded state for protected crash persistence.
    pub(crate) fn snapshot(&self) -> NetworkLifecycleRecoverySnapshotV1 {
        NetworkLifecycleRecoverySnapshotV1 {
            assignment: self.assignment,
            namespace: self.namespace,
            kernel: self.kernel,
            state: self.state,
            resource_digest: self.resource_digest,
            highest_sequence: self.highest_sequence,
            receipt_floor_sequence: self.receipt_floor_sequence,
            receipt_anchor_digest: self.receipt_anchor_digest,
            pending: self.pending,
            compacted_receipt_index: self.compacted_receipt_index.clone(),
            receipts: self.receipts.clone(),
            terminal_destroyed: self.terminal_destroyed,
            poisoned: self.poisoned,
            digest: self.snapshot_digest(),
        }
    }

    /// Compacts an exact receipt prefix only with protected journal authority.
    pub(crate) fn compact_receipts(
        &mut self,
        authority: ProtectedNetworkLifecycleCompactionV1,
    ) -> Result<(), NetworkLifecycleReducerError> {
        self.ensure_healthy()?;
        if self.pending.is_some()
            || authority.snapshot_digest != self.snapshot_digest()
            || authority.through_sequence <= self.receipt_floor_sequence
            || authority.through_sequence >= self.highest_sequence
        {
            return Err(NetworkLifecycleReducerError::CurrentnessMismatch);
        }
        let removed = self
            .receipts
            .iter()
            .take_while(|receipt| receipt.operation_sequence <= authority.through_sequence)
            .count();
        if removed == 0
            || self.receipts[removed - 1].operation_sequence != authority.through_sequence
        {
            return Err(NetworkLifecycleReducerError::StaleSequence);
        }
        let expected_anchor =
            receipt_compacted_anchor(&self.compacted_receipt_index, &self.receipts[..removed]);
        let expected_index =
            receipt_replay_index_digest(&self.compacted_receipt_index, &self.receipts);
        if authority.anchor_digest != expected_anchor
            || authority.replay_index_digest != expected_index
        {
            return Err(NetworkLifecycleReducerError::ObservationMismatch);
        }
        if self.compacted_receipt_index.len().saturating_add(removed) > MAXIMUM_COMPACTED_RECEIPTS {
            return Err(NetworkLifecycleReducerError::ReceiptHistoryExhausted);
        }
        self.compacted_receipt_index
            .extend(self.receipts.drain(..removed).map(compact_network_receipt));
        self.receipt_floor_sequence = authority.through_sequence;
        self.receipt_anchor_digest = Some(expected_anchor);
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<(), NetworkLifecycleReducerError> {
        if self.poisoned {
            Err(NetworkLifecycleReducerError::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn fence_digest(
    assignment: BrokerAssignment,
    lease_digest: ObjectDigest,
    lease_generation: u64,
    deadline: u64,
    session_digest: ObjectDigest,
    currentness_digest: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(FENCE_DOMAIN);
    update_assignment(&mut digest, assignment);
    digest.update(lease_digest.as_bytes());
    digest.update(lease_generation.to_be_bytes());
    digest.update(deadline.to_be_bytes());
    digest.update(session_digest.as_bytes());
    digest.update(currentness_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn kernel_identity_digest(
    namespace: NetworkNamespaceIdentityV1,
    plan_digest: ObjectDigest,
    policy_digest: ObjectDigest,
    links: NetworkLifecycleLinkIdentityV1,
    tc: NetworkLifecycleTcIdentityV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(OBJECT_IDENTITY_DOMAIN);
    update_namespace(&mut digest, namespace);
    digest.update(plan_digest.as_bytes());
    digest.update(policy_digest.as_bytes());
    update_links(&mut digest, links);
    update_tc(&mut digest, tc);
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn intent_digest(
    request_id: [u8; 16],
    sequence: u64,
    action: NetworkNamespaceLifecycleActionV1,
    prior_resource_digest: ObjectDigest,
    prior_catalog_digest: ObjectDigest,
    prior: NetworkNamespaceObservedStateV1,
    desired: NetworkNamespaceObservedStateV1,
    kernel_digest: ObjectDigest,
    fence_digest: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(INTENT_DOMAIN);
    digest.update(request_id);
    digest.update(sequence.to_be_bytes());
    digest.update([action_code(action)]);
    digest.update(prior_resource_digest.as_bytes());
    digest.update(prior_catalog_digest.as_bytes());
    update_state(&mut digest, prior);
    update_state(&mut digest, desired);
    digest.update(kernel_digest.as_bytes());
    digest.update(fence_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn observation_digest(
    intent_digest: ObjectDigest,
    fence_digest: ObjectDigest,
    prior_resource_digest: ObjectDigest,
    result_resource_digest: ObjectDigest,
    state: NetworkNamespaceObservedStateV1,
    disposition: NetworkLifecycleObservationDispositionV1,
    observed_boottime_nanoseconds: u64,
    observation_ordinal: u64,
    step_attempt_digest: ObjectDigest,
    release_digest: ObjectDigest,
    step_evidence_digest: ObjectDigest,
    residual_digest: ObjectDigest,
    first: ObjectDigest,
    second: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(OBSERVATION_DOMAIN);
    digest.update(intent_digest.as_bytes());
    digest.update(fence_digest.as_bytes());
    digest.update(prior_resource_digest.as_bytes());
    digest.update(result_resource_digest.as_bytes());
    update_state(&mut digest, state);
    match disposition {
        NetworkLifecycleObservationDispositionV1::Present(kernel) => {
            digest.update([0]);
            digest.update(kernel.digest().as_bytes());
        }
        NetworkLifecycleObservationDispositionV1::Destroyed(cleanup) => {
            digest.update([1]);
            digest.update(cleanup.digest.as_bytes());
        }
    }
    digest.update(observed_boottime_nanoseconds.to_be_bytes());
    digest.update(observation_ordinal.to_be_bytes());
    digest.update(step_attempt_digest.as_bytes());
    digest.update(release_digest.as_bytes());
    digest.update(step_evidence_digest.as_bytes());
    digest.update(residual_digest.as_bytes());
    digest.update(first.as_bytes());
    digest.update(second.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

impl NetworkLifecycleCleanupObservationV1 {
    fn has_complete_evidence(self, kernel_digest: ObjectDigest) -> bool {
        [
            self.namespace_absence_digest,
            self.link_absence_digest,
            self.bpffs_absence_digest,
            self.tc_absence_digest,
        ]
        .iter()
        .all(|digest| digest.as_bytes() != &[0; 32])
            && self.digest.as_bytes() != &[0; 32]
            && self.digest
                == cleanup_observation_digest(
                    kernel_digest,
                    self.namespace_absence_digest,
                    self.link_absence_digest,
                    self.bpffs_absence_digest,
                    self.tc_absence_digest,
                )
    }
}

fn cleanup_observation_digest(
    kernel_digest: ObjectDigest,
    namespace_absence_digest: ObjectDigest,
    link_absence_digest: ObjectDigest,
    bpffs_absence_digest: ObjectDigest,
    tc_absence_digest: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(CLEANUP_DOMAIN);
    digest.update(kernel_digest.as_bytes());
    digest.update(namespace_absence_digest.as_bytes());
    digest.update(link_absence_digest.as_bytes());
    digest.update(bpffs_absence_digest.as_bytes());
    digest.update(tc_absence_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn residual_digest(residual: NetworkLifecycleResidualV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(RESIDUAL_DOMAIN);
    digest.update(residual.intent_digest.as_bytes());
    update_assignment(&mut digest, residual.assignment);
    digest.update(residual.kernel_digest.as_bytes());
    update_state(&mut digest, residual.state);
    digest.update(residual.resource_digest.as_bytes());
    digest.update(residual.catalog_digest.as_bytes());
    digest.update(residual.currentness_digest.as_bytes());
    digest.update([
        residual.namespace as u8,
        residual.links as u8,
        residual.bpffs as u8,
        residual.tc as u8,
    ]);
    update_topology_residual(&mut digest, residual.topology);
    digest.update([residual.link_operational as u8]);
    digest.update([residual.action_progress as u8]);
    update_gate_residual(&mut digest, residual.gate);
    update_pin_teardown(&mut digest, residual.pin_teardown);
    digest.update(residual.observed_boottime_nanoseconds.to_be_bytes());
    digest.update(residual.observation_ordinal.to_be_bytes());
    digest.update(residual.first_snapshot_digest.as_bytes());
    digest.update(residual.second_snapshot_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn residual_semantic_digest(residual: NetworkLifecycleResidualV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.lifecycle-residual-semantics.v1\0");
    digest.update(residual.intent_digest.as_bytes());
    update_assignment(&mut digest, residual.assignment);
    digest.update(residual.kernel_digest.as_bytes());
    update_state(&mut digest, residual.state);
    digest.update(residual.resource_digest.as_bytes());
    digest.update(residual.catalog_digest.as_bytes());
    digest.update(residual.currentness_digest.as_bytes());
    digest.update([
        residual.namespace as u8,
        residual.links as u8,
        residual.bpffs as u8,
        residual.tc as u8,
    ]);
    update_topology_residual(&mut digest, residual.topology);
    digest.update([residual.link_operational as u8]);
    digest.update([residual.action_progress as u8]);
    update_gate_residual(&mut digest, residual.gate);
    update_pin_teardown(&mut digest, residual.pin_teardown);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn step_attempt_digest(attempt: NetworkLifecycleStepAttemptV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(STEP_ATTEMPT_DOMAIN);
    digest.update([attempt.step as u8]);
    digest.update(attempt.attempt_ordinal.to_be_bytes());
    digest.update(attempt.predecessor_residual.digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn plan_release_digest(
    intent_digest: ObjectDigest,
    step_attempt_digest: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(RELEASE_DOMAIN);
    digest.update(intent_digest.as_bytes());
    digest.update(step_attempt_digest.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn valid_step_attempt(attempt: NetworkLifecycleStepAttemptV1) -> bool {
    let release_shape_valid = match (
        attempt.released_boottime_nanoseconds,
        attempt.released_observation_ordinal,
    ) {
        (None, None) => true,
        (Some(boottime), Some(ordinal)) => {
            boottime >= attempt.predecessor_residual.observed_boottime_nanoseconds
                && ordinal > attempt.predecessor_residual.observation_ordinal
        }
        _ => false,
    };
    attempt.attempt_ordinal != 0
        && attempt.predecessor_residual.digest.as_bytes() != &[0; 32]
        && release_shape_valid
        && attempt
            .evidence_digest
            .is_none_or(|digest| digest.as_bytes() != &[0; 32])
        && attempt.digest == step_attempt_digest(attempt)
}

fn valid_recovered_pending(pending: PendingNetworkLifecycleV1) -> bool {
    if pending.latest_residual_digest.is_some() != pending.latest_residual.is_some()
        || pending.latest_residual.is_some() != pending.latest_disposition.is_some()
        || pending.latest_disposition.is_some_and(|disposition| {
            disposition
                != NetworkLifecycleObservationDispositionV1::Present(pending.intent.kernel())
        })
        || pending.latest_residual.is_some_and(|residual| {
            validate_residual(pending.intent, residual).is_err()
                || Some(residual_semantic_digest(residual)) != pending.latest_residual_digest
        })
    {
        return false;
    }
    if pending.latest_residual.is_none()
        && (pending.step_evidence_count != 0
            || pending.next_attempt_ordinal != 1
            || pending.any_effect_applied
            || pending.pin_teardown_phase != NetworkNamespacePinTeardownPhaseV1::Retained)
    {
        return false;
    }
    if pending.step_evidence_count != 0 {
        let Some(last_attempt) = pending.last_completed_attempt else {
            return false;
        };
        let Some(last_observation) = pending.last_observation else {
            return false;
        };
        let result_residual = if pending.phase == NetworkLifecycleReducerPhaseV1::Observed {
            pending.observed_residual
        } else {
            pending.latest_residual
        };
        let result_disposition = if pending.phase == NetworkLifecycleReducerPhaseV1::Observed {
            pending.observed_disposition
        } else {
            pending.latest_disposition
        };
        let Some(result_residual) = result_residual else {
            return false;
        };
        let Some(last_observation_ordinal) = pending.last_observation_ordinal else {
            return false;
        };
        if !valid_step_attempt(last_attempt)
            || last_attempt.attempt_ordinal != pending.step_evidence_count
            || last_attempt.evidence_digest.is_none()
            || pending.last_completed_residual_digest != Some(result_residual.digest)
            || last_observation.intent_digest != pending.intent.digest()
            || last_observation.fence_digest != pending.intent.fence().digest()
            || last_observation.prior_resource_digest != pending.intent.prior_resource_digest
            || last_observation.result_resource_digest != result_residual.resource_digest
            || last_observation.observed_state != result_residual.state
            || last_observation.residual != result_residual
            || Some(last_observation.disposition) != result_disposition
            || last_observation.step_attempt_digest != last_attempt.digest
            || Some(last_observation.step_evidence_digest) != last_attempt.evidence_digest
            || last_observation.release_digest
                != plan_release_digest(pending.intent.digest(), last_attempt.digest)
            || last_observation.observed_boottime_nanoseconds
                != result_residual.observed_boottime_nanoseconds
            || last_observation.observation_ordinal != result_residual.observation_ordinal
            || last_observation.digest
                != observation_digest(
                    last_observation.intent_digest,
                    last_observation.fence_digest,
                    last_observation.prior_resource_digest,
                    last_observation.result_resource_digest,
                    last_observation.observed_state,
                    last_observation.disposition,
                    last_observation.observed_boottime_nanoseconds,
                    last_observation.observation_ordinal,
                    last_observation.step_attempt_digest,
                    last_observation.release_digest,
                    last_observation.step_evidence_digest,
                    last_observation.residual.digest,
                    last_observation.first_snapshot_digest,
                    last_observation.second_snapshot_digest,
                )
            || last_observation.first_snapshot_digest.as_bytes() == &[0; 32]
            || last_observation.first_snapshot_digest != last_observation.second_snapshot_digest
            || last_observation.observation_ordinal
                <= last_attempt.predecessor_residual.observation_ordinal
            || last_attempt
                .released_observation_ordinal
                .is_none_or(|ordinal| last_observation.observation_ordinal <= ordinal)
            || last_attempt
                .released_boottime_nanoseconds
                .is_none_or(|boottime| last_observation.observed_boottime_nanoseconds < boottime)
            || result_residual.observation_ordinal != last_observation_ordinal
            || pending.step_evidence_anchor
                != Some(step_evidence_record_digest(
                    pending.step_evidence_count - 1,
                    pending.prior_step_evidence_anchor,
                    last_attempt,
                    result_residual.digest,
                    result_residual.observed_boottime_nanoseconds,
                    last_observation_ordinal,
                ))
        {
            return false;
        }
        if matches!(
            pending.phase,
            NetworkLifecycleReducerPhaseV1::Prepared
                | NetworkLifecycleReducerPhaseV1::EffectUnknown
        ) && (pending.last_released_boottime_nanoseconds
            != last_attempt.released_boottime_nanoseconds
            || pending.last_released_observation_ordinal
                != last_attempt.released_observation_ordinal)
        {
            return false;
        }
    }
    let Some(attempt) = pending.step_attempt else {
        return pending.phase == NetworkLifecycleReducerPhaseV1::Prepared
            && pending.latest_residual.is_none_or(|residual| {
                next_effect_step(pending.intent, residual)
                    .ok()
                    .flatten()
                    .is_some()
                    && pin_phase_matches_residual(pending.pin_teardown_phase, residual.pin_teardown)
            });
    };
    if pending.latest_residual.is_some_and(|latest| {
        residual_semantic_digest(latest) != residual_semantic_digest(attempt.predecessor_residual)
            || attempt.predecessor_residual.observation_ordinal <= latest.observation_ordinal
    }) || pending.latest_residual.is_none()
        && (attempt.predecessor_residual.resource_digest != pending.intent.prior_resource_digest
            || attempt.predecessor_residual.catalog_digest != pending.intent.prior_catalog_digest
            || attempt.predecessor_residual.currentness_digest
                != pending.intent.fence().currentness_digest()
            || attempt.predecessor_residual.state != pending.intent.prior_state
            || attempt.predecessor_residual.action_progress
                != NetworkLifecycleActionProgressV1::Initial)
    {
        return false;
    }
    if validate_residual(pending.intent, attempt.predecessor_residual).is_err()
        || next_effect_step(pending.intent, attempt.predecessor_residual)
            .ok()
            .flatten()
            != Some(attempt.step)
    {
        return false;
    }
    let pin_valid = match attempt.step {
        NetworkLifecycleEffectStepV1::RemoveNamespacePin => match (
            attempt.predecessor_residual.pin_teardown,
            pending.pin_teardown_phase,
        ) {
            (
                NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(left),
                NetworkNamespacePinTeardownPhaseV1::EffectUnknown(right),
            ) => left == right,
            (
                NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(left),
                NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(right),
            ) if pending.phase == NetworkLifecycleReducerPhaseV1::Observed => left == right,
            _ => false,
        },
        _ => pin_phase_matches_residual(
            pending.pin_teardown_phase,
            attempt.predecessor_residual.pin_teardown,
        ),
    };
    let observed_valid = match pending.observed_residual {
        None => pending.phase != NetworkLifecycleReducerPhaseV1::Observed,
        Some(residual) => {
            pending.phase == NetworkLifecycleReducerPhaseV1::Observed
                && pending.last_observation.is_some_and(|observation| {
                    pending.observation_digest == Some(observation.digest)
                        && pending.effect_applied == Some(pending.any_effect_applied)
                })
                && pending.observed_release_digest
                    == Some(plan_release_digest(pending.intent.digest(), attempt.digest))
                && validate_residual(pending.intent, residual).is_ok()
                && validate_step_progress(attempt.step, attempt.predecessor_residual, residual)
                    .is_ok()
                && validate_action_step_result(
                    pending.intent,
                    attempt.step,
                    attempt.predecessor_residual,
                    residual,
                )
                .is_ok()
                && Some(residual.resource_digest) == pending.result_resource_digest
                && valid_recovered_terminal_observation(pending, residual)
                && match (pending.intent.action(), pending.observed_disposition) {
                    (
                        NetworkNamespaceLifecycleActionV1::Destroy,
                        Some(NetworkLifecycleObservationDispositionV1::Destroyed(cleanup)),
                    ) => cleanup.has_complete_evidence(pending.intent.kernel().digest()),
                    (
                        NetworkNamespaceLifecycleActionV1::Arm
                        | NetworkNamespaceLifecycleActionV1::Renew
                        | NetworkNamespaceLifecycleActionV1::Disarm,
                        Some(NetworkLifecycleObservationDispositionV1::Present(kernel)),
                    ) => kernel == pending.intent.kernel(),
                    _ => false,
                }
        }
    };
    pin_valid && observed_valid
}

fn valid_recovered_terminal_observation(
    pending: PendingNetworkLifecycleV1,
    residual: NetworkLifecycleResidualV1,
) -> bool {
    let applied = pending.any_effect_applied;
    if pending.effect_applied != Some(applied) {
        return false;
    }

    match (pending.intent.action(), pending.observed_disposition) {
        (
            NetworkNamespaceLifecycleActionV1::Destroy,
            Some(NetworkLifecycleObservationDispositionV1::Destroyed(cleanup)),
        ) => {
            applied
                && residual.state == pending.intent.desired_state
                && residual.state == NetworkNamespaceObservedStateV1::absent()
                && residual.resource_digest != pending.intent.prior_resource_digest
                && cleanup.has_complete_evidence(pending.intent.kernel().digest())
                && matches!(
                    pending.pin_teardown_phase,
                    NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(digest)
                        if digest.as_bytes() != &[0; 32]
                )
        }
        (
            NetworkNamespaceLifecycleActionV1::Arm
            | NetworkNamespaceLifecycleActionV1::Renew
            | NetworkNamespaceLifecycleActionV1::Disarm,
            Some(NetworkLifecycleObservationDispositionV1::Present(kernel)),
        ) if kernel == pending.intent.kernel() => {
            if applied {
                residual.state == pending.intent.desired_state
                    && residual.resource_digest != pending.intent.prior_resource_digest
            } else {
                residual.state == pending.intent.prior_state
                    && residual.resource_digest == pending.intent.prior_resource_digest
            }
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn step_evidence_record_digest(
    prior_count: u64,
    prior_anchor: Option<ObjectDigest>,
    attempt: NetworkLifecycleStepAttemptV1,
    result_residual_digest: ObjectDigest,
    observed_boottime_nanoseconds: u64,
    observation_ordinal: u64,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(STEP_EVIDENCE_DOMAIN);
    digest.update(prior_count.to_be_bytes());
    update_optional_digest(&mut digest, prior_anchor);
    digest.update(attempt.digest.as_bytes());
    update_optional_u64(&mut digest, attempt.released_boottime_nanoseconds);
    update_optional_u64(&mut digest, attempt.released_observation_ordinal);
    update_optional_digest(&mut digest, attempt.evidence_digest);
    digest.update(result_residual_digest.as_bytes());
    digest.update(observed_boottime_nanoseconds.to_be_bytes());
    digest.update(observation_ordinal.to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn pending_digest(pending: PendingNetworkLifecycleV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(PENDING_DOMAIN);
    digest.update(pending.intent.digest().as_bytes());
    digest.update([phase_code(pending.phase)]);
    update_optional_digest(&mut digest, pending.observation_digest);
    update_optional_digest(&mut digest, pending.result_resource_digest);
    match pending.effect_applied {
        None => digest.update([0]),
        Some(value) => digest.update([1, u8::from(value)]),
    }
    update_optional_digest(&mut digest, pending.latest_residual_digest);
    match pending.latest_residual {
        None => digest.update([0]),
        Some(residual) => {
            digest.update([1]);
            digest.update(residual.digest.as_bytes());
        }
    }
    match pending.latest_disposition {
        None => digest.update([0]),
        Some(NetworkLifecycleObservationDispositionV1::Present(kernel)) => {
            digest.update([1]);
            digest.update(kernel.digest().as_bytes());
        }
        Some(NetworkLifecycleObservationDispositionV1::Destroyed(cleanup)) => {
            digest.update([2]);
            digest.update(cleanup.digest.as_bytes());
        }
    }
    digest.update(pending.next_attempt_ordinal.to_be_bytes());
    digest.update([u8::from(pending.any_effect_applied)]);
    digest.update(pending.step_evidence_count.to_be_bytes());
    update_optional_digest(&mut digest, pending.step_evidence_anchor);
    update_optional_digest(&mut digest, pending.prior_step_evidence_anchor);
    match pending.last_completed_attempt {
        None => digest.update([0]),
        Some(attempt) => {
            digest.update([1]);
            digest.update(attempt.digest.as_bytes());
            update_optional_u64(&mut digest, attempt.released_boottime_nanoseconds);
            update_optional_u64(&mut digest, attempt.released_observation_ordinal);
            update_optional_digest(&mut digest, attempt.evidence_digest);
        }
    }
    update_optional_digest(&mut digest, pending.last_completed_residual_digest);
    match pending.last_observation {
        None => digest.update([0]),
        Some(observation) => {
            digest.update([1]);
            digest.update(observation.digest.as_bytes());
        }
    }
    update_pin_teardown(&mut digest, pending.pin_teardown_phase);
    update_optional_u64(&mut digest, pending.last_released_boottime_nanoseconds);
    update_optional_u64(&mut digest, pending.last_released_observation_ordinal);
    update_optional_u64(&mut digest, pending.last_observation_ordinal);
    match pending.observed_residual {
        None => digest.update([0]),
        Some(residual) => {
            digest.update([1]);
            digest.update(residual.digest.as_bytes());
        }
    }
    match pending.observed_disposition {
        None => digest.update([0]),
        Some(NetworkLifecycleObservationDispositionV1::Present(kernel)) => {
            digest.update([1]);
            digest.update(kernel.digest().as_bytes());
        }
        Some(NetworkLifecycleObservationDispositionV1::Destroyed(cleanup)) => {
            digest.update([2]);
            digest.update(cleanup.digest.as_bytes());
        }
    }
    update_optional_digest(&mut digest, pending.observed_release_digest);
    match pending.step_attempt {
        None => digest.update([0]),
        Some(attempt) => {
            digest.update([1]);
            digest.update(attempt.digest.as_bytes());
            update_optional_u64(&mut digest, attempt.released_boottime_nanoseconds);
            update_optional_u64(&mut digest, attempt.released_observation_ordinal);
            update_optional_digest(&mut digest, attempt.evidence_digest);
        }
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn update_gate_residual(digest: &mut Sha256, gate: NetworkLifecycleGateResidualV1) {
    match gate {
        NetworkLifecycleGateResidualV1::Armed {
            lease_digest,
            lease_generation,
            fail_stop_boottime_nanoseconds,
        } => {
            digest.update([0]);
            digest.update(lease_digest.as_bytes());
            digest.update(lease_generation.to_be_bytes());
            digest.update(fail_stop_boottime_nanoseconds.to_be_bytes());
        }
        NetworkLifecycleGateResidualV1::DefaultDrop => digest.update([1]),
        NetworkLifecycleGateResidualV1::Absent => digest.update([2]),
        NetworkLifecycleGateResidualV1::Partial => digest.update([3]),
    }
}

fn update_topology_residual(digest: &mut Sha256, topology: NetworkLifecycleTopologyResidualV1) {
    match topology {
        NetworkLifecycleTopologyResidualV1::Isolated { loopback } => {
            digest.update([0, loopback as u8]);
        }
        NetworkLifecycleTopologyResidualV1::Veth {
            loopback,
            host_peer,
            sandbox_peer,
            addresses,
            routes,
            neighbors,
        } => digest.update([
            1,
            loopback as u8,
            host_peer as u8,
            sandbox_peer as u8,
            addresses as u8,
            routes as u8,
            neighbors as u8,
        ]),
    }
}

fn update_pin_teardown(digest: &mut Sha256, phase: NetworkNamespacePinTeardownPhaseV1) {
    match phase {
        NetworkNamespacePinTeardownPhaseV1::Retained => digest.update([0]),
        NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(value) => {
            digest.update([1]);
            digest.update(value.as_bytes());
        }
        NetworkNamespacePinTeardownPhaseV1::EffectUnknown(value) => {
            digest.update([2]);
            digest.update(value.as_bytes());
        }
        NetworkNamespacePinTeardownPhaseV1::ObservedAbsent(value) => {
            digest.update([3]);
            digest.update(value.as_bytes());
        }
    }
}

fn pin_phase_matches_residual(
    pending: NetworkNamespacePinTeardownPhaseV1,
    residual: NetworkNamespacePinTeardownPhaseV1,
) -> bool {
    pending == residual
        || matches!(
            (pending, residual),
            (
                NetworkNamespacePinTeardownPhaseV1::EffectUnknown(left),
                NetworkNamespacePinTeardownPhaseV1::BrokerAuthorized(right)
            ) if left == right
        )
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

fn receipt_integrity_digest(receipt: NetworkLifecycleReceiptV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(RECEIPT_DOMAIN);
    digest.update(receipt.request_id);
    digest.update(receipt.operation_sequence.to_be_bytes());
    digest.update([action_code(receipt.action)]);
    update_assignment(&mut digest, receipt.assignment);
    digest.update(receipt.intent_digest.as_bytes());
    digest.update(receipt.prior_resource_digest.as_bytes());
    digest.update(receipt.result_resource_digest.as_bytes());
    update_state(&mut digest, receipt.prior_state);
    update_state(&mut digest, receipt.result_state);
    digest.update(receipt.observation_digest.as_bytes());
    digest.update(receipt.kernel_digest.as_bytes());
    digest.update([u8::from(receipt.effect_applied)]);
    digest.update(receipt.step_evidence_count.to_be_bytes());
    digest.update(receipt.step_evidence_anchor.as_bytes());
    update_optional_u64(&mut digest, receipt.last_released_boottime_nanoseconds);
    update_optional_u64(&mut digest, receipt.last_released_observation_ordinal);
    digest.update(receipt.last_observation_ordinal.to_be_bytes());
    update_optional_digest(&mut digest, receipt.namespace_pin_teardown_digest);
    digest.update([u8::from(receipt.terminal_destroyed)]);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn valid_receipt_state_transition(receipt: NetworkLifecycleReceiptV1) -> bool {
    if !receipt.effect_applied {
        return receipt.action != NetworkNamespaceLifecycleActionV1::Destroy
            && receipt.action != NetworkNamespaceLifecycleActionV1::Fence
            && receipt.result_state == receipt.prior_state
            && receipt.result_resource_digest == receipt.prior_resource_digest;
    }

    if receipt.result_resource_digest == receipt.prior_resource_digest {
        return false;
    }

    match receipt.action {
        NetworkNamespaceLifecycleActionV1::Arm => {
            receipt.prior_state.kind() == NetworkNamespaceObservedStateKindV1::DefaultDrop
                && receipt.result_state.kind() == NetworkNamespaceObservedStateKindV1::Armed
        }
        NetworkNamespaceLifecycleActionV1::Renew => {
            receipt.prior_state.kind() == NetworkNamespaceObservedStateKindV1::Armed
                && receipt.result_state.kind() == NetworkNamespaceObservedStateKindV1::Armed
                && receipt.prior_state.lease().is_some_and(
                    |(_, prior_generation, prior_deadline)| {
                        receipt.result_state.lease().is_some_and(
                            |(_, result_generation, result_deadline)| {
                                result_generation > prior_generation
                                    && result_deadline > prior_deadline
                            },
                        )
                    },
                )
        }
        NetworkNamespaceLifecycleActionV1::Disarm => {
            matches!(
                receipt.prior_state.kind(),
                NetworkNamespaceObservedStateKindV1::Armed
                    | NetworkNamespaceObservedStateKindV1::Fenced
            ) && receipt.result_state.kind() == NetworkNamespaceObservedStateKindV1::DefaultDrop
        }
        NetworkNamespaceLifecycleActionV1::Destroy => {
            matches!(
                receipt.prior_state.kind(),
                NetworkNamespaceObservedStateKindV1::DefaultDrop
                    | NetworkNamespaceObservedStateKindV1::Fenced
            ) && receipt.result_state == NetworkNamespaceObservedStateV1::absent()
                && receipt.terminal_destroyed
                && matches!(
                    receipt.namespace_pin_teardown_digest,
                    Some(digest) if digest.as_bytes() != &[0; 32]
                )
        }
        NetworkNamespaceLifecycleActionV1::Fence => false,
    }
}

fn reducer_snapshot_digest(
    assignment: BrokerAssignment,
    namespace: NetworkNamespaceIdentityV1,
    kernel_digest: ObjectDigest,
    state: NetworkNamespaceObservedStateV1,
    resource_digest: ObjectDigest,
    highest_sequence: u64,
    receipt_floor_sequence: u64,
    receipt_anchor_digest: Option<ObjectDigest>,
    pending_digest: Option<ObjectDigest>,
    compacted_receipts: &[CompactedNetworkLifecycleReceiptV1],
    receipts: &[NetworkLifecycleReceiptV1],
    terminal_destroyed: bool,
    poisoned: bool,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(SNAPSHOT_DOMAIN);
    update_assignment(&mut digest, assignment);
    update_namespace(&mut digest, namespace);
    digest.update(kernel_digest.as_bytes());
    update_state(&mut digest, state);
    digest.update(resource_digest.as_bytes());
    digest.update(highest_sequence.to_be_bytes());
    digest.update(receipt_floor_sequence.to_be_bytes());
    update_optional_digest(&mut digest, receipt_anchor_digest);
    match pending_digest {
        None => digest.update([0]),
        Some(value) => {
            digest.update([1]);
            digest.update(value.as_bytes());
        }
    }
    digest.update((compacted_receipts.len() as u64).to_be_bytes());
    for value in compacted_receipts {
        digest.update(value.operation_sequence.to_be_bytes());
        digest.update(value.request_id);
        digest.update(value.intent_digest.as_bytes());
        digest.update(value.receipt_digest.as_bytes());
        digest.update(value.result_resource_digest.as_bytes());
        update_state(&mut digest, value.result_state);
        digest.update(value.kernel_digest.as_bytes());
    }
    digest.update((receipts.len() as u64).to_be_bytes());
    for value in receipts {
        digest.update(value.digest().as_bytes());
    }
    digest.update([u8::from(terminal_destroyed)]);
    digest.update([u8::from(poisoned)]);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn receipt_compacted_anchor(
    compacted: &[CompactedNetworkLifecycleReceiptV1],
    newly_compacted: &[NetworkLifecycleReceiptV1],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.lifecycle.compacted-anchor.v1\0");
    digest.update(((compacted.len() + newly_compacted.len()) as u64).to_be_bytes());
    for receipt in compacted {
        digest.update(receipt.operation_sequence.to_be_bytes());
        digest.update(receipt.request_id);
        digest.update(receipt.intent_digest.as_bytes());
        digest.update(receipt.receipt_digest.as_bytes());
        digest.update(receipt.result_resource_digest.as_bytes());
        update_state(&mut digest, receipt.result_state);
        digest.update(receipt.kernel_digest.as_bytes());
    }
    for receipt in newly_compacted {
        digest.update(receipt.operation_sequence.to_be_bytes());
        digest.update(receipt.request_id);
        digest.update(receipt.intent_digest.as_bytes());
        digest.update(receipt.digest.as_bytes());
        digest.update(receipt.result_resource_digest.as_bytes());
        update_state(&mut digest, receipt.result_state);
        digest.update(receipt.kernel_digest.as_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn receipt_replay_index_digest(
    compacted: &[CompactedNetworkLifecycleReceiptV1],
    retained: &[NetworkLifecycleReceiptV1],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.network.lifecycle.replay-index.v1\0");
    digest.update(((compacted.len() + retained.len()) as u64).to_be_bytes());
    for receipt in compacted {
        digest.update(receipt.operation_sequence.to_be_bytes());
        digest.update(receipt.request_id);
        digest.update(receipt.intent_digest.as_bytes());
        digest.update(receipt.receipt_digest.as_bytes());
        digest.update(receipt.result_resource_digest.as_bytes());
        update_state(&mut digest, receipt.result_state);
        digest.update(receipt.kernel_digest.as_bytes());
    }
    for receipt in retained {
        digest.update(receipt.operation_sequence.to_be_bytes());
        digest.update(receipt.request_id);
        digest.update(receipt.intent_digest.as_bytes());
        digest.update(receipt.digest.as_bytes());
        digest.update(receipt.result_resource_digest.as_bytes());
        update_state(&mut digest, receipt.result_state);
        digest.update(receipt.kernel_digest.as_bytes());
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn encode_recovery_checkpoint(
    snapshot: &NetworkLifecycleRecoverySnapshotV1,
    payload: &[u8],
) -> Result<Vec<u8>, NetworkLifecycleReducerError> {
    let indexed_count = snapshot.compacted_receipt_index.len() + snapshot.receipts.len();
    let count = u32::try_from(indexed_count)
        .map_err(|_| NetworkLifecycleReducerError::ReceiptHistoryExhausted)?;
    let capacity = 8usize
        .checked_add(2 + 8 + 1 + 32 + 32 + 4)
        .and_then(|value| value.checked_add(indexed_count.checked_mul(88)?))
        .and_then(|value| value.checked_add(4 + payload.len()))
        .ok_or(NetworkLifecycleReducerError::ReceiptHistoryExhausted)?;
    if capacity > MAXIMUM_RECOVERY_CHECKPOINT_BYTES {
        return Err(NetworkLifecycleReducerError::ReceiptHistoryExhausted);
    }
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(b"AOSNLRV1");
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&snapshot.receipt_floor_sequence.to_be_bytes());
    match snapshot.receipt_anchor_digest {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(value.as_bytes());
        }
    }
    if snapshot.receipt_anchor_digest.is_none() {
        bytes.extend_from_slice(&[0; 32]);
    }
    bytes.extend_from_slice(snapshot.digest.as_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    for receipt in &snapshot.compacted_receipt_index {
        bytes.extend_from_slice(&receipt.operation_sequence.to_be_bytes());
        bytes.extend_from_slice(&receipt.request_id);
        bytes.extend_from_slice(receipt.intent_digest.as_bytes());
        bytes.extend_from_slice(receipt.receipt_digest.as_bytes());
    }
    for receipt in &snapshot.receipts {
        bytes.extend_from_slice(&receipt.operation_sequence.to_be_bytes());
        bytes.extend_from_slice(&receipt.request_id);
        bytes.extend_from_slice(receipt.intent_digest.as_bytes());
        bytes.extend_from_slice(receipt.digest.as_bytes());
    }
    let payload_length = u32::try_from(payload.len())
        .map_err(|_| NetworkLifecycleReducerError::ReceiptHistoryExhausted)?;
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn compact_network_receipt(
    receipt: NetworkLifecycleReceiptV1,
) -> CompactedNetworkLifecycleReceiptV1 {
    CompactedNetworkLifecycleReceiptV1 {
        request_id: receipt.request_id,
        operation_sequence: receipt.operation_sequence,
        intent_digest: receipt.intent_digest,
        receipt_digest: receipt.digest,
        result_resource_digest: receipt.result_resource_digest,
        result_state: receipt.result_state,
        kernel_digest: receipt.kernel_digest,
    }
}

fn validate_recovery_checkpoint(
    bytes: &[u8],
    snapshot: &NetworkLifecycleRecoverySnapshotV1,
    payload: &[u8],
) -> Result<(), NetworkLifecycleReducerError> {
    if bytes.len() > MAXIMUM_RECOVERY_CHECKPOINT_BYTES
        || decode_recovery_checkpoint_header(bytes)?
            != (
                snapshot.receipt_floor_sequence,
                snapshot.receipt_anchor_digest,
                snapshot.digest,
                snapshot.compacted_receipt_index.len() + snapshot.receipts.len(),
            )
        || bytes != encode_recovery_checkpoint(snapshot, payload)?.as_slice()
    {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    Ok(())
}

fn decode_recovery_checkpoint_header(
    bytes: &[u8],
) -> Result<(u64, Option<ObjectDigest>, ObjectDigest, usize), NetworkLifecycleReducerError> {
    if bytes.len() < 87
        || bytes.len() > MAXIMUM_RECOVERY_CHECKPOINT_BYTES
        || &bytes[..8] != b"AOSNLRV1"
        || bytes[8..10] != 1u16.to_be_bytes()
    {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    let floor = u64::from_be_bytes(
        bytes[10..18]
            .try_into()
            .map_err(|_| NetworkLifecycleReducerError::ObservationMismatch)?,
    );
    let anchor_bytes: [u8; 32] = bytes[19..51]
        .try_into()
        .map_err(|_| NetworkLifecycleReducerError::ObservationMismatch)?;
    let anchor = match bytes[18] {
        0 if anchor_bytes == [0; 32] => None,
        1 if anchor_bytes != [0; 32] => Some(ObjectDigest::from_bytes(anchor_bytes)),
        _ => return Err(NetworkLifecycleReducerError::ObservationMismatch),
    };
    let snapshot_digest = ObjectDigest::from_bytes(
        bytes[51..83]
            .try_into()
            .map_err(|_| NetworkLifecycleReducerError::ObservationMismatch)?,
    );
    let count = u32::from_be_bytes(
        bytes[83..87]
            .try_into()
            .map_err(|_| NetworkLifecycleReducerError::ObservationMismatch)?,
    ) as usize;
    let payload_length_offset = 87usize.saturating_add(count.saturating_mul(88));
    if bytes.len() < payload_length_offset.saturating_add(4) {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    Ok((floor, anchor, snapshot_digest, count))
}

fn recovery_checkpoint_payload(bytes: &[u8]) -> Result<&[u8], NetworkLifecycleReducerError> {
    let (_, _, _, count) = decode_recovery_checkpoint_header(bytes)?;
    let offset = 87usize
        .checked_add(
            count
                .checked_mul(88)
                .ok_or(NetworkLifecycleReducerError::ObservationMismatch)?,
        )
        .ok_or(NetworkLifecycleReducerError::ObservationMismatch)?;
    let length = u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .map_err(|_| NetworkLifecycleReducerError::ObservationMismatch)?,
    ) as usize;
    let end = offset
        .checked_add(4)
        .and_then(|value| value.checked_add(length))
        .ok_or(NetworkLifecycleReducerError::ObservationMismatch)?;
    if end != bytes.len() {
        return Err(NetworkLifecycleReducerError::ObservationMismatch);
    }
    Ok(&bytes[offset + 4..end])
}

fn update_assignment(digest: &mut Sha256, assignment: BrokerAssignment) {
    digest.update(assignment.sandbox().as_bytes());
    digest.update(assignment.incarnation().as_bytes());
    digest.update(assignment.epoch().get().to_be_bytes());
    digest.update(assignment.desired_generation().get().to_be_bytes());
    digest.update(assignment.digest().as_bytes());
}

fn update_namespace(digest: &mut Sha256, namespace: NetworkNamespaceIdentityV1) {
    digest.update(namespace.network_handle());
    digest.update(namespace.kernel_boot_id());
    digest.update(namespace.namespace_device().to_be_bytes());
    digest.update(namespace.namespace_inode().to_be_bytes());
}

fn update_links(digest: &mut Sha256, links: NetworkLifecycleLinkIdentityV1) {
    match links {
        NetworkLifecycleLinkIdentityV1::Isolated { loopback_ifindex } => {
            digest.update([0]);
            digest.update(loopback_ifindex.to_be_bytes());
        }
        NetworkLifecycleLinkIdentityV1::Veth {
            loopback_ifindex,
            host_ifindex,
            sandbox_ifindex,
            host_link_digest,
            sandbox_link_digest,
        } => {
            digest.update([1]);
            digest.update(loopback_ifindex.to_be_bytes());
            digest.update(host_ifindex.to_be_bytes());
            digest.update(sandbox_ifindex.to_be_bytes());
            digest.update(host_link_digest.as_bytes());
            digest.update(sandbox_link_digest.as_bytes());
        }
    }
}

fn update_tc(digest: &mut Sha256, tc: NetworkLifecycleTcIdentityV1) {
    match tc {
        NetworkLifecycleTcIdentityV1::Absent => digest.update([0]),
        NetworkLifecycleTcIdentityV1::LeaseGate {
            bpffs_device,
            bpffs_inode,
            host_ingress_program_id,
            host_egress_program_id,
            lease_map_id,
            artifact_digest,
            loader_binding_digest,
        } => {
            digest.update([1]);
            digest.update(bpffs_device.to_be_bytes());
            digest.update(bpffs_inode.to_be_bytes());
            digest.update(host_ingress_program_id.to_be_bytes());
            digest.update(host_egress_program_id.to_be_bytes());
            digest.update(lease_map_id.to_be_bytes());
            digest.update(artifact_digest.as_bytes());
            digest.update(loader_binding_digest.as_bytes());
        }
    }
}

fn update_state(digest: &mut Sha256, state: NetworkNamespaceObservedStateV1) {
    digest.update([state_code(state.kind())]);
    match state.lease() {
        None => digest.update([0; 48]),
        Some((lease_digest, generation, deadline)) => {
            digest.update(lease_digest.as_bytes());
            digest.update(generation.to_be_bytes());
            digest.update(deadline.to_be_bytes());
        }
    }
}

const fn action_code(action: NetworkNamespaceLifecycleActionV1) -> u8 {
    match action {
        NetworkNamespaceLifecycleActionV1::Arm => 0,
        NetworkNamespaceLifecycleActionV1::Renew => 1,
        NetworkNamespaceLifecycleActionV1::Disarm => 2,
        NetworkNamespaceLifecycleActionV1::Fence => 3,
        NetworkNamespaceLifecycleActionV1::Destroy => 4,
    }
}

const fn state_code(state: NetworkNamespaceObservedStateKindV1) -> u8 {
    match state {
        NetworkNamespaceObservedStateKindV1::DefaultDrop => 0,
        NetworkNamespaceObservedStateKindV1::Armed => 1,
        NetworkNamespaceObservedStateKindV1::Fenced => 2,
        NetworkNamespaceObservedStateKindV1::Absent => 3,
    }
}

const fn phase_code(phase: NetworkLifecycleReducerPhaseV1) -> u8 {
    match phase {
        NetworkLifecycleReducerPhaseV1::Prepared => 0,
        NetworkLifecycleReducerPhaseV1::EffectUnknown => 1,
        NetworkLifecycleReducerPhaseV1::ReleaseFrozen => 2,
        NetworkLifecycleReducerPhaseV1::Observed => 3,
    }
}

const fn zero_digest() -> ObjectDigest {
    ObjectDigest::from_bytes([0; 32])
}
