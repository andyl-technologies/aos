//! Authenticated operational controls for host RAM and host deadlines.
//!
//! These controls bypass the modeled session command stream. The transport
//! supplies the authenticated principal; payloads cannot nominate an authority.
//! The executor implementation retains admission, idempotency, and live pager
//! ownership. [`codec`] uses bounded explicit-width records with no native ABI.
//!
//! ```text
//! u32 schema = 1 | u8 message tag | fixed-width fields in big-endian order
//! Optional: u8 0, or u8 1 followed by the value. Maximum message: 4096 bytes.
//! ```

use std::sync::Arc;
use std::time::Duration;

pub use crucible_linux_resource::host_supervision::{
    HostDeadlineSource, HostOperationBudget, HostOperationBudgets, HostOperationClass,
    HostOperationStatus, HostOuterCapStatus, HostProgressKind,
};
pub use crucible_linux_resource::ram_policy::{
    HostRamCapabilities, HostRamMode, HostRamPolicy, HostRamTarget, HostResourceVector,
};
/// Successful native pager activity, independent of RSS measurement availability.
pub use crucible_protocol::ram_control::RamControlActivity as HostRamActivity;

/// Canonical portable topology authenticated during pre-CPU RAM admission.
pub type HostRamInventoryTopology = crucible_ram::Topology;

/// Portable descriptor of one realized guest RAM region.
pub type HostRamInventoryRegion = crucible_ram::RegionDescriptor;

/// Closed region class used by canonical RAM inventory admission.
pub type HostRamInventoryRegionClass = crucible_ram::RegionClass;

/// Checked format limits applied before admitting a realized RAM inventory.
pub type HostRamInventoryLimits = crucible_ram::Limits;

/// Closed capture scope authenticated by a published RAM root.
pub type HostRamCaptureScope = crucible_ram::Scope;

mod backing;
pub mod codec;
pub use backing::{HostRamBackingError, HostRamBackingPartition};

/// Maximum canonical host-control request or response size.
pub const HOST_OPERATIONAL_MAX_BYTES: usize = 4096;

/// Maximum operation statuses in one coherent status observation.
pub const HOST_OPERATIONAL_MAX_OPERATIONS: usize = 12;

/// Maximum independently owned outer caps in one status observation.
pub const HOST_OPERATIONAL_MAX_OUTER_CAPS: usize = 4;

/// Maximum bounded limitation reasons in one status observation.
pub const HOST_OPERATIONAL_MAX_REASONS: usize = 8;

/// Maximum active RAM targets returned by one owner-bound discovery page.
pub const HOST_OPERATIONAL_MAX_TARGETS: usize = 32;

/// Exact daemon and execution namespace used to discover active RAM arenas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostRamOwnerTarget {
    /// Daemon incarnation that owns the registered arenas.
    pub daemon_epoch: [u8; 32],
    /// Immutable admitted execution identity.
    pub owner_id: [u8; 32],
}

/// Resource amendment reserved before the associated policy is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostReservationAmendment {
    /// Revision of the existing reservation being replaced.
    pub expected_reservation_revision: u64,
    /// Complete requested successor entitlement.
    pub requested: HostResourceVector,
    /// Peak retained through physical convergence and ownership reconciliation.
    pub transition_peak: HostResourceVector,
}

/// Exact independently supervised owner of an original-start outer cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostOuterCapOwner {
    /// One immutable execution incarnation.
    Execution([u8; 32]),
    /// One independently authenticated service incarnation.
    Service([u8; 32]),
}

/// Distinct authority target for an already registered original-start cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostOuterCapTarget {
    /// Daemon incarnation that owns the supervisor clock and durable authority.
    pub daemon_epoch: [u8; 32],
    /// Authenticated execution or service owner; these namespaces do not alias.
    pub owner: HostOuterCapOwner,
    /// Exact owner incarnation advanced without reuse on replacement.
    pub owner_generation: u64,
    /// Nonreused operational identity of an already registered cap.
    pub cap_id: [u8; 32],
}

/// Closed source class of an independently owned outer cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HostOuterCapClass {
    /// Immutable-start allowance attached to an admitted assignment.
    Assignment = 0,
    /// Independently supervised preparation lifetime.
    Preparation = 1,
    /// Original service shutdown and containment lifetime.
    ServiceShutdown = 2,
    /// Independently authorized operator lifetime.
    Operator = 3,
}

/// Complete target namespace selected by a host operational request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOperationalTarget {
    /// One execution namespace for bounded current-target discovery.
    Owner(HostRamOwnerTarget),
    /// One live node or retained-template RAM arena.
    Ram(HostRamTarget),
    /// One existing independent supervisor cap.
    OuterCap(HostOuterCapTarget),
}

/// A generation-bound operational request, separate from modeled commands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostOperationalRequest {
    /// Lists current arenas without guessing their independently allocated generations.
    ///
    /// Pages are live observations, not a frozen lifecycle snapshot. A target
    /// can retire between discovery and a subsequent generation-bound request.
    ListTargets {
        /// Exact daemon and admitted execution namespace.
        target: HostRamOwnerTarget,
        /// Exclusive ordered cursor from a previous page, if any.
        after: Option<HostRamTarget>,
        /// Positive requested page size, at most 32.
        limit: u8,
    },
    /// Observes independently qualified behavior for one live target.
    Capabilities {
        /// Exact live ownership incarnation.
        target: HostRamTarget,
    },
    /// Observes policy and physical convergence without scanning guest RAM.
    Status {
        /// Exact live ownership incarnation.
        target: HostRamTarget,
    },
    /// Commits a desired policy after durable idempotency and admission.
    UpdatePolicy {
        /// Exact live ownership incarnation.
        target: HostRamTarget,
        /// Expected current policy revision for a new unique request.
        expected_policy_revision: u64,
        /// Target-lifetime unique request key; retries retain this key.
        idempotency_key: [u8; 32],
        /// Desired successor policy, excluding modeled guest state.
        policy: Box<HostRamPolicy>,
        /// Optional separately revisioned resource admission change.
        reservation_amendment: Option<HostReservationAmendment>,
    },
    /// Changes an outer allowance measured from its original host start.
    AmendOuterCap {
        /// Exact execution and arena ownership incarnation.
        target: HostOuterCapTarget,
        /// Expected independent outer-cap revision.
        expected_cap_revision: u64,
        /// Durable idempotency identity for this amendment.
        idempotency_key: [u8; 32],
        /// Original-start allowance; absent explicitly removes the outer cap.
        allowance: Option<Duration>,
    },
}

impl HostOperationalRequest {
    /// Returns the complete live ownership target.
    #[must_use]
    pub const fn target(&self) -> HostOperationalTarget {
        match self {
            Self::ListTargets { target, .. } => HostOperationalTarget::Owner(*target),
            Self::Capabilities { target }
            | Self::Status { target }
            | Self::UpdatePolicy { target, .. } => HostOperationalTarget::Ram(*target),
            Self::AmendOuterCap { target, .. } => HostOperationalTarget::OuterCap(*target),
        }
    }

    /// Reports whether this request can change operational ownership or policy.
    #[must_use]
    pub const fn is_mutating(&self) -> bool {
        matches!(self, Self::UpdatePolicy { .. } | Self::AmendOuterCap { .. })
    }
}

/// Physical state of a requested residency transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HostRamConvergence {
    /// Requested and applied policy have reached their measured target.
    Stable = 0,
    /// Policy has been accepted and physical application is pending.
    Applying = 1,
    /// Authenticated writeback and safe eviction are in progress.
    Evicting = 2,
    /// Bounded, cancellable prefetch is in progress.
    Prefetching = 3,
    /// A resource or safe-boundary condition prevents convergence.
    Blocked = 4,
    /// The transition failed operationally while retaining preservation authority.
    Failed = 5,
    /// Ownership remains contained pending safe cleanup.
    Quarantined = 6,
}

/// Status of one independently owned original-start outer cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostOuterCapObservation {
    /// Authenticated operational owner identity; never a guest identity hash.
    pub target: HostOuterCapTarget,
    /// Immutable source class; amendments cannot relabel the cap.
    pub class: HostOuterCapClass,
    /// Independently revisioned allowance and current limiting disposition.
    pub status: HostOuterCapStatus,
}

/// Coherent policy, ownership, measurement, and deadline observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRamStatus {
    /// Complete live ownership incarnation.
    pub target: HostRamTarget,
    /// Monotonic coherent observation identity within this target.
    pub observation_sequence: u64,
    /// Accepted desired-policy revision.
    pub policy_revision: u64,
    /// Independently owned resource reservation revision.
    pub reservation_revision: u64,
    /// Most recently accepted desired policy.
    pub requested_policy: HostRamPolicy,
    /// Policy established by the physical arena manager.
    pub applied_policy: HostRamPolicy,
    /// Achievable guest-page resident target after compulsory floors.
    pub effective_resident_target_bytes: u64,
    /// Compulsory resident floor included in the target accounting.
    pub effective_floor_bytes: u64,
    /// Bounded operational reasons why the requested target is limited.
    pub limitation_reasons: Vec<String>,
    /// Indicates whether the coherent physical byte counters are available.
    pub measurements_available: bool,
    /// Optional actual native transition counters; absence means unavailable.
    pub activity: Option<HostRamActivity>,
    /// Measured private resident guest-page bytes.
    pub private_resident_bytes: u64,
    /// Observed shared bytes; this does not duplicate the template reservation.
    pub shared_resident_bytes_observed: u64,
    /// Preserved guest contents charged to backing ownership.
    pub preserved_backing_bytes: u64,
    /// Private dirty guest-page bytes.
    pub private_dirty_bytes: u64,
    /// Dirty bytes awaiting committed preservation.
    pub writeback_pending_bytes: u64,
    /// Observed physical convergence state.
    pub convergence: HostRamConvergence,
    /// Accepted unique updates retained in target-lifetime history.
    pub accepted_unique_update_count: u64,
    /// Remaining admitted unique-update capacity.
    pub remaining_unique_update_capacity: u64,
    /// Authoritatively retained policy-history disk bytes.
    pub history_disk_bytes: u64,
    /// Current physical transition, if one remains active.
    pub transition: Option<u64>,
    /// Complete currently reserved resource entitlement.
    pub admitted_resources: HostResourceVector,
    /// Separately revisioned original-start caps, in canonical owner order.
    pub outer_caps: Vec<HostOuterCapObservation>,
    /// Outstanding host operations, ordered by their nonreused identities.
    pub outstanding_operations: Vec<HostOperationStatus>,
}

/// Closed disposition of an authenticated operational mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HostOperationalDisposition {
    /// The request was durably accepted; physical convergence remains separate.
    Accepted = 0,
    /// The original acceptance was returned for an identical retry.
    Replayed = 1,
    /// A new unique request carried an obsolete expected revision.
    RevisionConflict = 2,
    /// The target incarnation is no longer current.
    NotCurrent = 3,
    /// A requested behavior lacks qualified backend support.
    Unsupported = 4,
    /// Complete transition resources could not be reserved.
    AdmissionRefused = 5,
    /// Durable history capacity could not be reserved before mutation.
    HistoryCapacityRefused = 6,
    /// Authenticated principal request-rate admission refused the request.
    RateLimited = 7,
    /// A coherent ownership authority is temporarily unavailable.
    Unavailable = 8,
    /// The original-start cap has a sticky terminal disposition.
    Terminal = 9,
}

/// Independently deployed and qualified host RAM mechanism.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum HostRamBackend {
    /// Ordinary guest mappings with full guest-RAM peak admission.
    #[default]
    FullyResident = 0,
    /// Host kernel reclamation used solely for residency measurements.
    KernelSwapMeasurement = 1,
    /// Authenticated pager removing mappings only at coherent paused boundaries.
    PausedPager = 2,
    /// Qualified fault-safe pager with a separately proven bounded execution peak.
    StrictPager = 3,
}

/// Explicit qualification separate from a backend's operational preferences.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostRamQualification {
    /// Mechanism actually installed on this live target.
    pub backend: HostRamBackend,
    /// Cold generations are authenticated before any guest consumer is unblocked.
    pub authenticated_pages: bool,
    /// Fault servicing can reclaim capacity independently of guest progress.
    pub fault_safe_progress: bool,
    /// The advertised sub-RAM execution peak has passed its native proof and gates.
    pub bounded_execution_peak: bool,
    /// Mostly-cold live forks have passed lifecycle and ownership qualification.
    pub hot_fork: bool,
    /// Authenticated mostly-cold restores have passed lazy activation qualification.
    pub lazy_restore: bool,
    /// Complete bounded closures have passed authenticated transfer qualification.
    pub authenticated_transfer: bool,
    /// Immutable deployment qualification receipt binding the enabled capabilities.
    pub evidence: Option<[u8; 32]>,
}

/// Typed operational result retaining acceptance independently of convergence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostOperationalResponse {
    /// Bounded sorted active arenas observed within one authenticated owner.
    Targets {
        /// Exact namespace of this observation.
        target: HostRamOwnerTarget,
        /// Strictly increasing current target identities.
        targets: Vec<HostRamTarget>,
        /// Last returned target when another page was observed to exist.
        next: Option<HostRamTarget>,
    },
    /// Independently qualified live backend capabilities.
    Capabilities {
        /// Authenticated target of this observation.
        target: HostRamTarget,
        /// Measured capacity and explicitly qualified backend behavior.
        capabilities: HostRamCapabilities,
        /// Independently established deployment qualification, not inferred from configuration.
        qualification: HostRamQualification,
    },
    /// Coherent physical and operational status.
    Status(Box<HostRamStatus>),
    /// Original or newly committed policy acceptance.
    PolicyUpdate {
        /// Domain-separated digest binding principal and complete canonical request.
        request_digest: [u8; 32],
        /// Complete target incarnation.
        target: HostRamTarget,
        /// Acceptance or typed operational refusal.
        disposition: HostOperationalDisposition,
        /// Accepted policy revision, or current revision on conflict.
        policy_revision: u64,
        /// Independently admitted reservation revision.
        reservation_revision: u64,
        /// Physical transition identity, when accepted.
        transition: Option<u64>,
        /// Original accepted policy, absent for a refused unique request.
        accepted_policy: Option<Box<HostRamPolicy>>,
    },
    /// Original or newly committed independent outer-cap amendment.
    OuterCapAmendment {
        /// Domain-separated digest of the complete authenticated request.
        request_digest: [u8; 32],
        /// Complete target incarnation.
        target: HostOuterCapTarget,
        /// Acceptance or typed refusal, independent of policy revision.
        disposition: HostOperationalDisposition,
        /// Originally accepted revision, absent for a refused unique request.
        accepted_cap_revision: Option<u64>,
        /// Original accepted allowance; outer absence means refusal, inner absence removes the cap.
        accepted_allowance: Option<Option<Duration>>,
    },
}

/// Fail-closed error at the operational control boundary.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HostOperationalError {
    /// The transport principal does not own operational authority for this target.
    #[error("host operational principal is denied")]
    PrincipalDenied,
    /// A request or response violates its bounded canonical contract.
    #[error("invalid host operational message: {message}")]
    InvalidMessage {
        /// Bounded diagnostic describing the violated field.
        message: String,
    },
    /// No live operational controller is installed for this incarnation.
    #[error("host operational target is unavailable")]
    Unavailable,
    /// One durable key was reused with different authenticated canonical bytes.
    #[error("host operational idempotency key was reused with different bytes")]
    IdempotencyConflict,
}

/// Executor-owned authority over live operational controllers and durable history.
pub trait HostOperationalControl: Send + Sync {
    /// Authenticates and executes one bounded request against live ownership.
    ///
    /// The principal is supplied by the transport, never by request bytes.
    /// Implementations must authenticate exact ownership before idempotency
    /// lookup, reserve history and resources before acceptance, and dispatch to
    /// the existing live watchdog and arena controller.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed authorization, malformed-message, unavailable-owner,
    /// or conflicting-idempotency error. Operational refusals are typed results.
    fn execute(
        &self,
        principal: &str,
        request: HostOperationalRequest,
    ) -> Result<HostOperationalResponse, HostOperationalError>;
}

/// Shared live executor operational authority installed on the API control plane.
pub type SharedHostOperationalControl = Arc<dyn HostOperationalControl>;

/// Computes a domain-separated digest binding the operator and entire request.
///
/// # Errors
///
/// Returns an error for a malformed principal or noncanonical request fields.
pub fn host_operational_request_digest(
    principal: &str,
    request: &HostOperationalRequest,
) -> Result<[u8; 32], HostOperationalError> {
    if principal.is_empty() || principal.len() > 255 || principal.chars().any(char::is_control) {
        return Err(HostOperationalError::PrincipalDenied);
    }
    let bytes = codec::encode_request(request)?;
    let mut digest = blake3::Hasher::new();
    digest.update(b"crucible.host-ram.request.v1\0");
    digest.update(&(principal.len() as u32).to_be_bytes());
    digest.update(principal.as_bytes());
    digest.update(&bytes);
    Ok(*digest.finalize().as_bytes())
}
