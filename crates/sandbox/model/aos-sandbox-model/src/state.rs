//! Portable desired-state and observed-state machines.
//!
//! The controller persists desired lifecycle separately from node observation.
//! Each observed resource has a closed transition graph so stale or impossible
//! reports fail before they can replace durable status. Replaying the same
//! state is accepted to make reconciliation idempotent.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{DesiredGeneration, ObservationSequence};

/// Defines the transition contract required by an observed resource phase.
pub trait ObservedPhase: Copy + Eq + fmt::Debug {
    /// Reports whether `next` is a valid edge or an idempotent observation.
    fn can_transition_to(self, next: Self) -> bool;
}

/// Reports an edge that is absent from a resource's closed transition graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTransition<S> {
    from: S,
    to: S,
}

impl<S> InvalidTransition<S> {
    /// Returns the state from which the rejected transition began.
    #[must_use]
    pub const fn from(&self) -> &S {
        &self.from
    }

    /// Returns the rejected destination state.
    #[must_use]
    pub const fn to(&self) -> &S {
        &self.to
    }
}

impl<S: fmt::Debug> fmt::Display for InvalidTransition<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid state transition from {:?} to {:?}",
            self.from, self.to
        )
    }
}

impl<S: fmt::Debug> std::error::Error for InvalidTransition<S> {}

macro_rules! transition_methods {
    ($state:ident, $body:expr) => {
        impl ObservedPhase for $state {
            fn can_transition_to(self, next: Self) -> bool {
                self == next || $body(self, next)
            }
        }

        impl $state {
            /// Reports whether `next` is an allowed transition or an
            /// idempotent observation of the current state.
            #[must_use]
            pub fn can_transition_to(self, next: Self) -> bool {
                ObservedPhase::can_transition_to(self, next)
            }

            /// Validates and returns `next`.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidTransition`] when the edge is absent from this
            /// resource's closed transition graph.
            pub fn transition(self, next: Self) -> Result<Self, InvalidTransition<Self>> {
                if self.can_transition_to(next) {
                    Ok(next)
                } else {
                    Err(InvalidTransition {
                        from: self,
                        to: next,
                    })
                }
            }
        }
    };
}

/// Stores a bounded stable reason suitable for metrics, policy, and automation.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ReasonCode(String);

impl ReasonCode {
    /// Creates a reason code from lowercase ASCII components separated by `.`
    /// or `-`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidReasonCode`] when the value is empty, exceeds 128
    /// bytes, starts or ends with a separator, contains adjacent separators,
    /// or contains bytes outside the closed alphabet.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidReasonCode> {
        let value = value.into();
        let mut component_has_byte = false;

        if value.is_empty() || value.len() > 128 {
            return Err(InvalidReasonCode);
        }

        for byte in value.bytes() {
            match byte {
                b'a'..=b'z' | b'0'..=b'9' => component_has_byte = true,
                b'.' | b'-' if component_has_byte => component_has_byte = false,
                _ => return Err(InvalidReasonCode),
            }
        }

        if !component_has_byte {
            return Err(InvalidReasonCode);
        }

        Ok(Self(value))
    }

    /// Returns the stable reason code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ReasonCode {
    type Error = InvalidReasonCode;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ReasonCode> for String {
    fn from(value: ReasonCode) -> Self {
        value.0
    }
}

/// Reports a malformed machine-readable transition reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("reason code must contain 1..=128 lowercase ASCII component bytes")]
pub struct InvalidReasonCode;

/// Records a wall-clock transition time without relying on it for ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TransitionTime {
    seconds: i64,
    nanoseconds: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionTimeWire {
    seconds: i64,
    nanoseconds: u32,
}

impl<'de> Deserialize<'de> for TransitionTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TransitionTimeWire::deserialize(deserializer)?;
        Self::new(wire.seconds, wire.nanoseconds).map_err(serde::de::Error::custom)
    }
}

impl TransitionTime {
    /// Creates a Unix timestamp with a normalized nanosecond component.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTransitionTime`] if `nanoseconds` is one billion or
    /// greater.
    pub const fn new(seconds: i64, nanoseconds: u32) -> Result<Self, InvalidTransitionTime> {
        if nanoseconds < 1_000_000_000 {
            Ok(Self {
                seconds,
                nanoseconds,
            })
        } else {
            Err(InvalidTransitionTime)
        }
    }

    /// Returns whole seconds since the Unix epoch.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Returns the normalized subsecond nanosecond component.
    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }
}

/// Reports a non-normalized transition timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("transition timestamp nanoseconds must be less than one billion")]
pub struct InvalidTransitionTime;

/// Couples a resource phase to ordering and diagnostic metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedState<S> {
    phase: S,
    desired_generation: DesiredGeneration,
    sequence: ObservationSequence,
    reason: ReasonCode,
    transition_time: TransitionTime,
}

impl<S: ObservedPhase> ObservedState<S> {
    /// Creates an initial observed state.
    #[must_use]
    pub const fn new(
        phase: S,
        desired_generation: DesiredGeneration,
        sequence: ObservationSequence,
        reason: ReasonCode,
        transition_time: TransitionTime,
    ) -> Self {
        Self {
            phase,
            desired_generation,
            sequence,
            reason,
            transition_time,
        }
    }

    /// Returns the observed resource phase.
    #[must_use]
    pub const fn phase(&self) -> S {
        self.phase
    }

    /// Returns the desired generation this observation reconciles.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the strictly monotonic observation sequence.
    #[must_use]
    pub const fn sequence(&self) -> ObservationSequence {
        self.sequence
    }

    /// Returns the stable machine-readable transition reason.
    #[must_use]
    pub const fn reason(&self) -> &ReasonCode {
        &self.reason
    }

    /// Returns the diagnostic wall-clock transition time.
    #[must_use]
    pub const fn transition_time(&self) -> TransitionTime {
        self.transition_time
    }

    /// Validates and constructs the next durable observation.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationAdvanceError`] if the desired generation moves
    /// backward, the sequence does not strictly advance, or the phase edge is
    /// invalid.
    pub fn advance(
        &self,
        phase: S,
        desired_generation: DesiredGeneration,
        sequence: ObservationSequence,
        reason: ReasonCode,
        transition_time: TransitionTime,
    ) -> Result<Self, ObservationAdvanceError<S>> {
        if desired_generation < self.desired_generation {
            return Err(ObservationAdvanceError::StaleDesiredGeneration {
                current: self.desired_generation,
                proposed: desired_generation,
            });
        }
        if !sequence.is_newer_than(self.sequence) {
            return Err(ObservationAdvanceError::StaleSequence {
                current: self.sequence,
                proposed: sequence,
            });
        }
        if !self.phase.can_transition_to(phase) {
            return Err(ObservationAdvanceError::InvalidPhase(InvalidTransition {
                from: self.phase,
                to: phase,
            }));
        }

        Ok(Self::new(
            phase,
            desired_generation,
            sequence,
            reason,
            transition_time,
        ))
    }
}

/// Reports why a proposed observation cannot replace durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationAdvanceError<S> {
    /// The report names an older desired generation.
    StaleDesiredGeneration {
        /// Currently accepted desired generation.
        current: DesiredGeneration,
        /// Generation named by the rejected report.
        proposed: DesiredGeneration,
    },
    /// The report does not strictly advance the node observation sequence.
    StaleSequence {
        /// Currently accepted observation sequence.
        current: ObservationSequence,
        /// Sequence named by the rejected report.
        proposed: ObservationSequence,
    },
    /// The phase edge is absent from the resource transition graph.
    InvalidPhase(InvalidTransition<S>),
}

impl<S: fmt::Debug> fmt::Display for ObservationAdvanceError<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleDesiredGeneration { current, proposed } => write!(
                formatter,
                "desired generation {} is older than current generation {}",
                proposed.get(),
                current.get()
            ),
            Self::StaleSequence { current, proposed } => write!(
                formatter,
                "observation sequence {} does not advance current sequence {}",
                proposed.get(),
                current.get()
            ),
            Self::InvalidPhase(error) => error.fmt(formatter),
        }
    }
}

impl<S: fmt::Debug> std::error::Error for ObservationAdvanceError<S> {}

/// Selects how a suspended sandbox retains runtime state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuspensionMode {
    /// Retains the frozen payload, namespaces, mounts, and memory on one node.
    MemoryResident,
    /// Commits a durable snapshot and stops the runtime.
    Hibernate,
}

/// Declares the lifecycle state the controller must reconcile toward.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "state", content = "mode")]
pub enum DesiredSandboxState {
    /// Requires a ready runtime with all hard policy installed.
    Running,
    /// Requires a suspended runtime or durable hibernation snapshot.
    Suspended(SuspensionMode),
    /// Requires no running payload while retaining the logical sandbox.
    Stopped,
    /// Tombstones the resource and requires complete cleanup.
    Deleted,
}

impl DesiredSandboxState {
    /// Reports whether a compare-and-swap may select `next`.
    ///
    /// Deletion is irreversible. Every other desired lifecycle change is a
    /// new generation and may select any non-deleted state.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        !matches!(self, Self::Deleted) || matches!(next, Self::Deleted)
    }

    /// Validates and returns a new desired state.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTransition`] if an operation attempts to resurrect a
    /// tombstoned sandbox.
    pub fn transition(self, next: Self) -> Result<Self, InvalidTransition<Self>> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(InvalidTransition {
                from: self,
                to: next,
            })
        }
    }
}

/// Describes the node-observed realization phase of a sandbox.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxPhase {
    /// Durable intent exists but preparation has not begun.
    Requested,
    /// Host resources and policy plans are being prepared.
    Preparing,
    /// The runtime has been launched but is not ready.
    Starting,
    /// Runtime and every required attachment and hard policy are installed.
    Ready,
    /// Admissions are closed and the payload is being frozen.
    Freezing,
    /// The active incarnation and its memory remain frozen.
    Frozen,
    /// The runtime is being stopped.
    Stopping,
    /// No payload is active and durable sandbox state remains.
    Stopped,
    /// A durable resume snapshot exists and no incarnation is active.
    Hibernated,
    /// Resource cleanup is in progress after a tombstone committed.
    Deleting,
    /// All owned resources are released.
    Deleted,
    /// Reconciliation encountered a typed error that permits policy-defined retry.
    Error,
    /// The active node or memory-only incarnation can no longer be observed.
    Lost,
}

const fn sandbox_edge(from: SandboxPhase, to: SandboxPhase) -> bool {
    use SandboxPhase as S;
    matches!(
        (from, to),
        (S::Requested, S::Preparing | S::Deleting | S::Error)
            | (
                S::Preparing,
                S::Starting | S::Stopping | S::Deleting | S::Error | S::Lost
            )
            | (S::Starting, S::Ready | S::Stopping | S::Error | S::Lost)
            | (
                S::Ready,
                S::Freezing | S::Stopping | S::Deleting | S::Error | S::Lost
            )
            | (
                S::Freezing,
                S::Ready | S::Frozen | S::Stopping | S::Error | S::Lost
            )
            | (S::Frozen, S::Ready | S::Stopping | S::Error | S::Lost)
            | (
                S::Stopping,
                S::Stopped | S::Hibernated | S::Deleting | S::Error | S::Lost
            )
            | (
                S::Stopped,
                S::Preparing | S::Deleting | S::Hibernated | S::Error
            )
            | (S::Hibernated, S::Preparing | S::Deleting | S::Error)
            | (S::Error, S::Preparing | S::Stopping | S::Deleting | S::Lost)
            | (S::Lost, S::Preparing | S::Stopping | S::Deleting | S::Error)
            | (S::Deleting, S::Deleted | S::Error)
    )
}

transition_methods!(SandboxPhase, sandbox_edge);

/// Describes the observed phase of one sandbox execution.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionPhase {
    /// The execution request exists but has no committed reservation.
    Requested,
    /// Incarnation, limits, environment, and route commitments are durable.
    Admitted,
    /// The guest is starting the command.
    Starting,
    /// The command is running.
    Running,
    /// The command exited and its final status is recorded.
    Exited,
    /// Cancellation won before a normal exit was observed.
    Canceled,
    /// Admission or execution failed with a typed diagnostic.
    Failed,
}

const fn execution_edge(from: ExecutionPhase, to: ExecutionPhase) -> bool {
    use ExecutionPhase as E;
    matches!(
        (from, to),
        (E::Requested, E::Admitted | E::Canceled | E::Failed)
            | (E::Admitted, E::Starting | E::Canceled | E::Failed)
            | (
                E::Starting,
                E::Running | E::Exited | E::Canceled | E::Failed
            )
            | (E::Running, E::Exited | E::Canceled | E::Failed)
    )
}

transition_methods!(ExecutionPhase, execution_edge);

/// Describes the observed realization phase of a filesystem attachment.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttachmentPhase {
    /// Desired attachment metadata is durable.
    Declared,
    /// The broker is constructing a detached realization.
    Preparing,
    /// A mount or service endpoint occupies the broker-owned slot.
    Attached,
    /// Post-attachment identity and policy verification succeeded.
    Ready,
    /// New use is closed while existing references are revoked or drained.
    Draining,
    /// The realization and its leases have been released.
    Released,
    /// Preparation, verification, use, or release failed.
    Faulted,
}

const fn attachment_edge(from: AttachmentPhase, to: AttachmentPhase) -> bool {
    use AttachmentPhase as A;
    matches!(
        (from, to),
        (A::Declared, A::Preparing | A::Draining | A::Faulted)
            | (A::Preparing, A::Attached | A::Draining | A::Faulted)
            | (A::Attached, A::Ready | A::Draining | A::Faulted)
            | (A::Ready, A::Preparing | A::Draining | A::Faulted)
            | (A::Draining, A::Released | A::Faulted)
            | (A::Faulted, A::Preparing | A::Draining | A::Released)
    )
}

transition_methods!(AttachmentPhase, attachment_edge);

/// Describes the observed availability phase of a filesystem view.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ViewPhase {
    /// Desired view metadata is durable.
    Declared,
    /// Portable metadata is being validated and indexed.
    Indexing,
    /// The view can serve new attachments.
    Available,
    /// The view remains usable with an explicit bounded degradation.
    Degraded,
    /// New attachments are closed while consumers drain.
    Draining,
    /// Workers, pins, and registrations are released.
    Released,
}

const fn view_edge(from: ViewPhase, to: ViewPhase) -> bool {
    use ViewPhase as V;
    matches!(
        (from, to),
        (V::Declared, V::Indexing | V::Draining)
            | (V::Indexing, V::Available | V::Degraded | V::Draining)
            | (V::Available, V::Degraded | V::Draining)
            | (V::Degraded, V::Indexing | V::Available | V::Draining)
            | (V::Draining, V::Released)
    )
}

transition_methods!(ViewPhase, view_edge);

/// Describes the durable commit phase of a snapshot transaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotPhase {
    /// Snapshot intent exists but quiescence has not begun.
    Requested,
    /// Barriers, storage points, holds, and a manifest are being prepared.
    Preparing,
    /// The manifest is verified and every retention proposal is staged.
    Prepared,
    /// The durable semantic commit record is being installed.
    Committing,
    /// The verified manifest and every retention acknowledgement are durable.
    Committed,
    /// Snapshot deletion is draining dependencies and releasing holds.
    Deleting,
    /// The snapshot and its owned retention state are gone.
    Deleted,
    /// Pre-commit work failed and compensation is required or complete.
    FailedBeforeCommit,
    /// Committed state is safe but residual cleanup requires reconciliation.
    CommittedWithResidualCleanup,
    /// Policy or an external dependency permanently prevents progress.
    PermanentlyBlocked,
}

const fn snapshot_edge(from: SnapshotPhase, to: SnapshotPhase) -> bool {
    use SnapshotPhase as S;
    matches!(
        (from, to),
        (
            S::Requested,
            S::Preparing | S::FailedBeforeCommit | S::PermanentlyBlocked
        ) | (
            S::Preparing,
            S::Prepared | S::FailedBeforeCommit | S::PermanentlyBlocked
        ) | (
            S::Prepared,
            S::Committing | S::FailedBeforeCommit | S::PermanentlyBlocked
        ) | (
            S::Committing,
            S::Committed | S::CommittedWithResidualCleanup | S::PermanentlyBlocked
        ) | (S::Committed, S::Deleting | S::CommittedWithResidualCleanup)
            | (
                S::CommittedWithResidualCleanup,
                S::Committed | S::Deleting | S::PermanentlyBlocked
            )
            | (S::PermanentlyBlocked, S::Preparing | S::Deleting)
            | (S::Deleting, S::Deleted | S::PermanentlyBlocked)
    )
}

transition_methods!(SnapshotPhase, snapshot_edge);

/// Describes the durable progress of a consequential operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationPhase {
    /// The request and its preconditions are durably accepted.
    Accepted,
    /// Reversible resources and effect proposals are being prepared.
    Preparing,
    /// All prerequisites for the semantic commit point are satisfied.
    ReadyToCommit,
    /// The semantic commit point is durable and effects are reconciling.
    Committed,
    /// Pre-commit effects are being compensated in reverse order.
    Compensating,
    /// The committed desired state and all required effects converged.
    Succeeded,
    /// Preparation failed and no semantic resource was published.
    FailedBeforeCommit,
    /// Cancellation won before the semantic commit point.
    CanceledBeforeCommit,
    /// Desired state committed but bounded cleanup remains.
    CommittedWithResidualCleanup,
    /// Policy or an external dependency permanently prevents convergence.
    PermanentlyBlocked,
}

const fn operation_edge(from: OperationPhase, to: OperationPhase) -> bool {
    use OperationPhase as O;
    matches!(
        (from, to),
        (
            O::Accepted,
            O::Preparing | O::CanceledBeforeCommit | O::FailedBeforeCommit
        ) | (
            O::Preparing,
            O::ReadyToCommit | O::Compensating | O::CanceledBeforeCommit | O::FailedBeforeCommit
        ) | (
            O::ReadyToCommit,
            O::Committed | O::Compensating | O::CanceledBeforeCommit | O::FailedBeforeCommit
        ) | (
            O::Compensating,
            O::FailedBeforeCommit | O::CanceledBeforeCommit | O::PermanentlyBlocked
        ) | (
            O::Committed,
            O::Succeeded | O::CommittedWithResidualCleanup | O::PermanentlyBlocked
        )
    )
}

transition_methods!(OperationPhase, operation_edge);

/// Describes a node assignment's ownership and fail-stop progress.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssignmentPhase {
    /// A coordinator proposal exists but the node has not accepted it.
    Proposed,
    /// The semantic tuple is durable on the assigned node.
    Accepted,
    /// The ownership lease and fail-stop guardian are being armed.
    Arming,
    /// The guardian is armed and the node may admit assignment effects.
    Active,
    /// New effects are closed while the assignment is relinquished.
    Draining,
    /// Lease loss or supersession has fenced payload and external networking.
    Fenced,
    /// Every assignment-scoped effect has been released.
    Released,
    /// Preparation failed before active ownership was established.
    Failed,
}

const fn assignment_edge(from: AssignmentPhase, to: AssignmentPhase) -> bool {
    use AssignmentPhase as A;
    matches!(
        (from, to),
        (A::Proposed, A::Accepted | A::Failed)
            | (A::Accepted, A::Arming | A::Draining | A::Fenced | A::Failed)
            | (A::Arming, A::Active | A::Draining | A::Fenced | A::Failed)
            | (A::Active, A::Draining | A::Fenced)
            | (A::Draining, A::Fenced | A::Released)
            | (A::Fenced, A::Released)
            | (A::Failed, A::Draining | A::Released)
    )
}

transition_methods!(AssignmentPhase, assignment_edge);

#[cfg(test)]
mod tests {
    use super::{
        AssignmentPhase, AttachmentPhase, DesiredSandboxState, ExecutionPhase, ObservedState,
        OperationPhase, ReasonCode, SandboxPhase, SnapshotPhase, SuspensionMode, TransitionTime,
        ViewPhase,
    };
    use crate::{DesiredGeneration, ObservationSequence};

    #[test]
    fn idempotent_observations_are_always_accepted() {
        assert_eq!(
            SandboxPhase::Ready.transition(SandboxPhase::Ready),
            Ok(SandboxPhase::Ready)
        );
        assert_eq!(
            OperationPhase::Succeeded.transition(OperationPhase::Succeeded),
            Ok(OperationPhase::Succeeded)
        );
    }

    #[test]
    fn terminal_states_do_not_resurrect() {
        assert!(
            SandboxPhase::Deleted
                .transition(SandboxPhase::Preparing)
                .is_err()
        );
        assert!(
            ExecutionPhase::Exited
                .transition(ExecutionPhase::Running)
                .is_err()
        );
        assert!(
            AttachmentPhase::Released
                .transition(AttachmentPhase::Preparing)
                .is_err()
        );
        assert!(ViewPhase::Released.transition(ViewPhase::Indexing).is_err());
        assert!(
            SnapshotPhase::Deleted
                .transition(SnapshotPhase::Preparing)
                .is_err()
        );
        assert!(
            AssignmentPhase::Released
                .transition(AssignmentPhase::Active)
                .is_err()
        );
        assert!(
            OperationPhase::CommittedWithResidualCleanup
                .transition(OperationPhase::Succeeded)
                .is_err()
        );
        assert!(
            OperationPhase::PermanentlyBlocked
                .transition(OperationPhase::Preparing)
                .is_err()
        );
    }

    #[test]
    fn deletion_is_irreversible_in_desired_state() {
        let deleted = DesiredSandboxState::Deleted;

        assert!(deleted.transition(DesiredSandboxState::Running).is_err());
        assert_eq!(
            deleted.transition(DesiredSandboxState::Deleted),
            Ok(deleted)
        );
        assert!(
            DesiredSandboxState::Running
                .transition(DesiredSandboxState::Suspended(
                    SuspensionMode::MemoryResident
                ))
                .is_ok()
        );
    }

    #[test]
    fn cancellation_cannot_cross_the_commit_point() {
        assert!(
            OperationPhase::Preparing
                .transition(OperationPhase::CanceledBeforeCommit)
                .is_ok()
        );
        assert!(
            OperationPhase::Committed
                .transition(OperationPhase::CanceledBeforeCommit)
                .is_err()
        );
    }

    #[test]
    fn attachment_replacement_returns_to_preparing() {
        assert_eq!(
            AttachmentPhase::Ready.transition(AttachmentPhase::Preparing),
            Ok(AttachmentPhase::Preparing)
        );
    }

    #[test]
    fn assignment_must_arm_before_becoming_active() {
        assert!(
            AssignmentPhase::Accepted
                .transition(AssignmentPhase::Active)
                .is_err()
        );
        assert_eq!(
            AssignmentPhase::Arming.transition(AssignmentPhase::Active),
            Ok(AssignmentPhase::Active)
        );
    }

    #[test]
    fn observed_state_rejects_stale_and_impossible_reports() {
        let Ok(reason) = ReasonCode::new("runtime.starting") else {
            panic!("static reason must be valid");
        };
        let Ok(time) = TransitionTime::new(100, 42) else {
            panic!("static time must be valid");
        };
        let initial = ObservedState::new(
            SandboxPhase::Starting,
            DesiredGeneration::new(7),
            ObservationSequence::new(10),
            reason,
            time,
        );

        let Ok(ready_reason) = ReasonCode::new("runtime.ready") else {
            panic!("static reason must be valid");
        };
        let Ok(next_time) = TransitionTime::new(101, 0) else {
            panic!("static time must be valid");
        };
        assert!(
            initial
                .advance(
                    SandboxPhase::Ready,
                    DesiredGeneration::new(6),
                    ObservationSequence::new(11),
                    ready_reason.clone(),
                    next_time,
                )
                .is_err()
        );
        assert!(
            initial
                .advance(
                    SandboxPhase::Ready,
                    DesiredGeneration::new(7),
                    ObservationSequence::new(10),
                    ready_reason.clone(),
                    next_time,
                )
                .is_err()
        );
        assert!(
            initial
                .advance(
                    SandboxPhase::Deleted,
                    DesiredGeneration::new(7),
                    ObservationSequence::new(11),
                    ready_reason,
                    next_time,
                )
                .is_err()
        );
    }

    #[test]
    fn reason_and_time_are_bounded() {
        assert!(ReasonCode::new("view.cache-miss").is_ok());
        assert!(ReasonCode::new("View.CacheMiss").is_err());
        assert!(ReasonCode::new("view..miss").is_err());
        assert!(TransitionTime::new(-1, 999_999_999).is_ok());
        assert!(TransitionTime::new(0, 1_000_000_000).is_err());

        let decoded =
            serde_json::from_str::<TransitionTime>(r#"{"seconds":0,"nanoseconds":1000000000}"#);
        assert!(decoded.is_err());
    }

    #[test]
    fn fencing_acceptance_is_exact_for_generation_and_sequence_order() {
        let reason = ReasonCode::new("property.fence")
            .unwrap_or_else(|error| panic!("static reason failed: {error}"));
        let time =
            TransitionTime::new(0, 0).unwrap_or_else(|error| panic!("static time failed: {error}"));
        let current = ObservedState::new(
            SandboxPhase::Starting,
            DesiredGeneration::new(7),
            ObservationSequence::new(10),
            reason.clone(),
            time,
        );

        for generation in 0..=14 {
            for sequence in 0..=20 {
                let result = current.advance(
                    SandboxPhase::Starting,
                    DesiredGeneration::new(generation),
                    ObservationSequence::new(sequence),
                    reason.clone(),
                    time,
                );
                assert_eq!(result.is_ok(), generation >= 7 && sequence > 10);
            }
        }
    }

    #[test]
    fn deleted_sandbox_rejects_every_distinct_phase() {
        let phases = [
            SandboxPhase::Requested,
            SandboxPhase::Preparing,
            SandboxPhase::Starting,
            SandboxPhase::Ready,
            SandboxPhase::Freezing,
            SandboxPhase::Frozen,
            SandboxPhase::Stopping,
            SandboxPhase::Stopped,
            SandboxPhase::Hibernated,
            SandboxPhase::Deleting,
            SandboxPhase::Deleted,
            SandboxPhase::Error,
            SandboxPhase::Lost,
        ];

        for phase in phases {
            assert_eq!(
                SandboxPhase::Deleted.transition(phase).is_ok(),
                phase == SandboxPhase::Deleted
            );
        }
    }
}
