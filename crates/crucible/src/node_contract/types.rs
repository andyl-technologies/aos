//! Typed runtime observations, effect knowledge, and node operation permissions.

use std::{rc::Rc, time::Duration};

use crucible_node_contract::{
    ContentRef, Id, IncarnationId, NodeId, OperationId, OwnerId, Position, U64,
};

/// Identifies one owner incarnation in a realized world.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerIdentity {
    /// Stable execution or capture owner identity.
    pub owner: OwnerId,
    /// Fresh physical realization identity.
    pub incarnation: IncarnationId,
    /// Positive live owner generation, distinct from stable identity.
    pub generation: U64,
}

/// Resolves a public node to its authoritative mutable owners.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRoute {
    /// Stable public node identity.
    pub node: NodeId,
    /// Owners locked together before any node operation begins.
    pub owners: Vec<OwnerIdentity>,
}

/// Declares process-local adapter thread custody without imposing `Send`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadAffinity {
    /// Native adapter callbacks must run on this original host thread.
    OwnerThread(std::thread::ThreadId),
    /// Callbacks proxy work to a separately supervised owning actor.
    OwningActor,
}

impl ThreadAffinity {
    pub(crate) fn permits_current_thread(self) -> bool {
        match self {
            Self::OwnerThread(owner) => owner == std::thread::current().id(),
            Self::OwningActor => true,
        }
    }
}

/// Separates lifecycle from physical activity and modeled scheduling state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Lifecycle {
    /// Native resources have not been created.
    Unrealized,
    /// Native resources exist with ordinary execution withheld.
    Prepared,
    /// The logical operation or observation window is closed.
    Stopped,
    /// An operation has an outstanding completion obligation.
    Executing,
    /// A failure retains resources and known effects under supervision.
    FailedContained,
    /// Custody is retained pending containment or reclamation.
    Quarantined,
    /// All native obligations have been discharged.
    Released,
}

/// Describes physical suspension independently of logical window closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PhysicalState {
    /// An authentic provider acknowledgement establishes physical suspension.
    Suspended,
    /// Native execution or autonomous physical activity continues.
    Active,
    /// Available evidence does not establish physical activity or suspension.
    Unknown,
}

/// Reports lifecycle without inventing a stopped native boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatus {
    /// Resource and operation lifecycle.
    pub lifecycle: Lifecycle,
    /// Separately established physical activity.
    pub physical: PhysicalState,
    /// Authentic boundary, absent when the provider has not established one.
    pub boundary: Option<Position>,
}

/// Names an explicitly acquired optional role-independent facet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FacetKind {
    /// Exact causal execution ceilings.
    ExactExecution,
    /// Quantized input and output windows.
    QuantizedExecution,
    /// Physical suspension, independent of window closure.
    PhysicalPause,
    /// Complete declared state preservation.
    Preservation,
    /// Conditional or repeatable replay.
    Replay,
    /// Admitted modeled fault application.
    FaultInjection,
    /// Nonperturbing coverage observation.
    Coverage,
    /// Architectural state observation.
    Introspection,
    /// Separately admitted debugging operations.
    Debugging,
    /// Whole-world-fenced terminal host assertion evaluation.
    TerminalAssertions,
}

/// Defines the permission for a single common operation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OperationRequest {
    /// Grants a half-open exact semantic interval.
    ExactRun {
        /// Original authentic start coordinate.
        start: Position,
        /// Exclusive semantic ceiling.
        limit: Position,
        /// Qualified administrative stop semantics at the exclusive ceiling.
        boundary_policy: ExactBoundaryPolicy,
    },
    /// Grants a finite same-instant range of superdense settlement positions.
    BoundarySettle {
        /// First authorized phase and microstep at the original physical tick.
        start: Position,
        /// Exclusive phase and microstep bound at the same physical tick.
        limit: Position,
    },
    /// Activates one fully staged quantized start batch.
    QuantumBegin {
        /// Original window identity retained through closure.
        window: Id,
        /// Inclusive start boundary.
        start: Position,
        /// Earliest logical output publication boundary.
        end: Position,
        /// Closed, immutable input-batch identity.
        input_batch: Id,
        /// Operational execution budget, never simulation time.
        host_budget: Duration,
    },
    /// Requests closure of the original outstanding window.
    QuantumClose {
        /// Original window identity; never a replacement run.
        window: Id,
    },
    /// Requests genuine physical suspension.
    Pause,
    /// Inspects an admitted boundary without semantic mutation.
    Observe,
    /// Captures the reached state without modeled draining or execution.
    Capture,
    /// Applies one selected recorded coefficient transition at BoundaryControl.
    ///
    /// This explicit grammar does not authorize latency or topology changes.
    FaultInjectionV1(Box<super::FaultMutationRequest>),
    /// Executes selected original condition stop or resume under a live fence.
    ///
    /// This independent grammar never authorizes architectural guest mutation.
    DebugConditionV1(Box<super::ConditionControlRequest>),
    /// Finalizes assertions under original opaque whole-world admission.
    FinalizeAssertions {
        /// Retains original live-scope facts without issuing public authority.
        barrier: Box<super::WorldTerminalRecord>,
        /// Binds exact canonical original barrier bytes.
        receipt: ContentRef,
    },
    /// Ends semantic access and initiates supervised native shutdown.
    Shutdown,
}

/// Selects authentic nonexecuting exact ceiling semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExactBoundaryPolicy {
    /// Permits administrative horizon parking without a transition at the limit.
    HorizonPark,
    /// Also permits a qualified input-blocked park awaiting boundary arbitration.
    InputBlockedPark,
}

impl OperationRequest {
    pub(crate) fn required_facet(&self) -> Option<FacetKind> {
        match self {
            Self::ExactRun { .. } | Self::BoundarySettle { .. } => Some(FacetKind::ExactExecution),
            Self::QuantumBegin { .. } | Self::QuantumClose { .. } => {
                Some(FacetKind::QuantizedExecution)
            }
            Self::Pause => Some(FacetKind::PhysicalPause),
            Self::FinalizeAssertions { .. } => Some(FacetKind::TerminalAssertions),
            Self::Capture => Some(FacetKind::Preservation),
            Self::DebugConditionV1(_) => Some(FacetKind::Debugging),
            Self::FaultInjectionV1(_) => Some(FacetKind::FaultInjection),
            Self::Observe | Self::Shutdown => None,
        }
    }
}

/// Distinguishes native outcome evidence from the requested permission.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProgressEvidence {
    /// Reports exact reached position and authentic stop semantics.
    Exact {
        /// Actual reached coordinate, not the requested ceiling.
        reached: Position,
        /// Why semantic execution stopped.
        stop: StopReason,
    },
    /// Reports logical closure independently of physical activity.
    Quantized {
        /// Original quantum identity.
        window: Id,
        /// Logical boundary where outputs may be published.
        publication: Position,
        /// Native physical suspension or continued autonomous activity.
        physical: PhysicalState,
        /// Complete closure evidence validated by the authentic native adapter.
        closure: Box<QuantumClosureEvidence>,
    },
    /// Carries physical stop evidence without inventing a logical coordinate.
    Paused {
        /// Actual boundary when known.
        reached: Option<Position>,
        /// Native physical stop acknowledgement, not a logical window closure.
        stop_receipt: ContentRef,
    },
    /// Retains exact original terminal assertion report and barrier custody.
    AssertionsFinalized {
        /// Retains the authentic whole-world terminal cut.
        reached: Position,
        /// Retains the original barrier receipt.
        barrier: ContentRef,
        /// Binds original canonical report bytes under native custody.
        report: ContentRef,
    },
    /// Retains the original native coefficient mutation without modeled progress.
    FaultMutationApplied {
        /// Preserves the actual unchanged BoundaryControl cut.
        reached: Position,
        /// Binds exact original native operation/context/table record bytes.
        receipt: ContentRef,
        /// Retains the selected immutable controller identity.
        program: ContentRef,
        /// Retains the original decision ordinal.
        decision: U64,
    },
    /// Retains original native condition-control evidence at its unchanged cut.
    DebugConditionAppliedV1 {
        /// Retains the actual stopped native cut, with no fabricated execution.
        reached: Position,
        /// Names the original stop whose report and resume remain associated.
        stop_operation: Id,
        /// Binds the original authentic whole-world barrier.
        barrier: ContentRef,
        /// Binds the original native diagnostic report.
        report: ContentRef,
        /// Binds this original native control receipt (report for initial stop).
        control: ContentRef,
        /// Distinguishes native resume from initial condition-stop reporting.
        resumed: bool,
    },
    /// Reports an observational or lifecycle result with no fabricated progress.
    Administrative,
}

/// Retains the native evidence required to settle the original quantum window.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuantumClosureEvidence {
    /// Original closed input batch, unchanged from admission.
    pub input_batch: Id,
    /// Authentic native closure receipt.
    pub close_receipt: ContentRef,
    /// Complete ordered original output inventory.
    pub output_inventory: ContentRef,
    /// Complete disposition of pending native requests and input custody.
    pub pending_inventory: ContentRef,
    /// Declared controller-clock and native timer enforcement evidence.
    pub clock_evidence: ContentRef,
}

/// Names the actual reason exact execution stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StopReason {
    /// Administrative park at the exclusive ceiling with no transition there.
    HorizonPark,
    /// A retained outgoing event requires coordinator arbitration.
    Output,
    /// An unresolved input prevents further execution.
    InputBlocked,
    /// A guest request requires coordinator arbitration.
    GuestRequest,
    /// A qualified complete wake inventory established idle progress.
    IdleProof,
    /// A declared lifecycle transition stopped execution.
    Lifecycle,
    /// The stop lacks sufficient semantic classification for continuation.
    Unclassified,
}

/// Classifies effects when native execution fails.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EffectKnowledge {
    /// The adapter positively establishes that no native effect began.
    None,
    /// An identified original prefix committed and remains retained.
    CommittedPrefix(Vec<Id>),
    /// Native execution may have progressed.
    MayHaveProgressed,
    /// Available evidence cannot establish which effects occurred.
    Unknown,
}

/// Reports a no-effect refusal before native dispatch.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    /// Stable diagnostic describing the unmet precondition.
    pub reason: String,
}

/// Reports submission without mistaking transport acknowledgement for completion.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Submission {
    /// No effect began; the original reservation can be released.
    Refused(Refusal),
    /// The original operation now has an outstanding completion obligation.
    Accepted,
    /// Submission may have taken effect and must remain under containment.
    Uncertain(EffectKnowledge),
}

/// Retains the original outcome, including its publication obligation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationOutcome {
    /// Original operation identity.
    pub operation: OperationId,
    /// Original public component identity.
    pub node: NodeId,
    /// Complete original mutable-owner roster.
    pub owners: Vec<OwnerIdentity>,
    /// Actual progress and stop evidence.
    pub progress: ProgressEvidence,
    /// Ordered original outputs awaiting publication acknowledgement.
    pub retained_outputs: Vec<Id>,
    /// Complete authentic native scheduling inventory, when the profile supplies it.
    pub scheduling: Option<crate::node_scheduling::NativeSchedulingObservation>,
}

/// Reports a failed accepted operation while retaining native custody.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationFailure {
    /// Effect knowledge governing reconciliation or containment.
    pub effects: EffectKnowledge,
    /// Human-readable native failure diagnostic.
    pub reason: String,
}

/// Reports cancellation as a request, never as rollback or completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelStatus {
    /// The provider will attempt to terminate the original operation.
    Requested,
    /// The request already exists and remains pending.
    AlreadyRequested,
    /// The original operation already has a retained terminal result.
    Terminal,
    /// Cancellation is unsupported; original custody remains intact.
    Unsupported,
}

/// Carries local authority for one original operation.
///
/// Tokens have no public constructor or serialized representation. Dropping a
/// token does not release the runtime's retained native operation obligations.
#[derive(Clone, Debug)]
pub struct OperationToken {
    pub(crate) authority: Rc<()>,
    pub(crate) operation: OperationId,
    pub(crate) route: NodeRoute,
}

impl OperationToken {
    /// Tests whether two tokens retain the same original operation authority.
    ///
    /// This compares actual local custody together with its immutable operation
    /// and owner route. Equal public labels from another runtime do not match.
    /// A positive result authenticates token identity only; it does not establish
    /// native completion, current suspension or publication authority.
    pub fn same_authority(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.authority, &other.authority)
            && self.operation == other.operation
            && self.route == other.route
    }

    /// Returns the immutable original operation identity.
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// Returns the immutable original node and owner association.
    pub fn route(&self) -> &NodeRoute {
        &self.route
    }
}

/// Carries a coordinator-validated process-local dispatch permission.
#[derive(Clone, Debug)]
pub struct OperationAdmission {
    pub(crate) token: OperationToken,
    pub(crate) request: OperationRequest,
    pub(crate) activation: super::WorldActivation,
    pub(crate) inputs: Option<std::rc::Rc<crate::node_scheduling::RuntimeInputBatch>>,
}

impl OperationAdmission {
    /// Returns the original complete durably committed activation authority.
    pub fn activation(&self) -> &super::WorldActivation {
        &self.activation
    }

    /// Returns the frozen original staged input cut, if this grant carries input.
    pub fn inputs(&self) -> Option<&crate::node_scheduling::RuntimeInputBatch> {
        self.inputs.as_deref()
    }

    /// Returns the original operation token retained by the coordinator.
    pub fn token(&self) -> &OperationToken {
        &self.token
    }

    /// Returns the immutable requested permission.
    pub fn request(&self) -> &OperationRequest {
        &self.request
    }
}

/// Reports a local admission failure before provider effects begin.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    /// An admitted runtime or retained inventory ceiling would be exceeded.
    #[error("runtime resource ceiling exceeded")]
    ResourceLimit,
    /// Dispatch would violate the admitted native adapter's thread custody.
    #[error("native adapter thread affinity mismatch")]
    ThreadAffinity,
    /// The complete activated graph could not establish scheduling authority.
    #[error("scheduler admission failed: {0}")]
    SchedulerRefused(String),
    /// The requested public node was not admitted.
    #[error("unknown node")]
    UnknownNode,
    /// A route is missing owners or aliases an incompatible incarnation.
    #[error("invalid owner route")]
    InvalidRoute,
    /// An operation identity was already used in this world.
    #[error("operation identity already used")]
    DuplicateOperation,
    /// A shared owner has unresolved operation or publication custody.
    #[error("owner has retained operation custody")]
    OwnerBusy,
    /// An owner is contained or released and unavailable for ordinary work.
    #[error("owner is unavailable")]
    OwnerUnavailable,
    /// Complete world activation has not been durably established.
    #[error("world activation is not committed")]
    NotActivated,
    /// A token or activation record belongs to another local authority.
    #[error("foreign or stale authority")]
    ForeignAuthority,
    /// A required explicitly advertised facet is absent.
    #[error("unsupported facet")]
    UnsupportedFacet,
    /// A timing request has empty, inverted, or incompatible bounds.
    #[error("invalid timing request")]
    InvalidTiming,
    /// A provider result does not match the original admitted operation.
    #[error("invalid provider receipt; owner quarantined")]
    InvalidReceipt,
    /// Native terminal outcome or output acknowledgement is still outstanding.
    #[error("retained obligations remain")]
    OutstandingObligations,
    /// A durable publication failed or has uncertain status.
    #[error("activation publication failed or is uncertain")]
    PublicationFailed,
}

/// Bounds host routing and retained operation custody before native dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeLimits {
    /// Maximum complete public participant roster.
    pub maximum_nodes: usize,
    /// Maximum complete mutable-owner roster.
    pub maximum_owners: usize,
    /// Maximum original operations retained without recycling authority.
    pub maximum_operations: usize,
    /// Maximum original output identities in one terminal inventory.
    pub maximum_retained_outputs: usize,
}

/// Reports actual native owner reclamation without claiming effect rollback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeReclamationReceipt {
    /// Original owner incarnation whose native obligations were checked.
    pub owner: OwnerIdentity,
    /// Authenticated receipt establishing native resource reclamation.
    pub receipt: ContentRef,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            maximum_nodes: 65_536,
            maximum_owners: 65_536,
            maximum_operations: 65_536,
            maximum_retained_outputs: 65_536,
        }
    }
}

/// Returns the original submission disposition and retained local token.
#[derive(Clone, Debug)]
pub enum BeginResult {
    /// The provider positively refused without effects.
    Refused(Refusal),
    /// The original operation remains outstanding.
    Accepted(OperationToken),
    /// Effects are uncertain and the same operation remains under containment.
    Uncertain {
        /// Original retained operation association.
        token: OperationToken,
        /// Actual native effect knowledge.
        effects: EffectKnowledge,
    },
}

/// Observes original retained operation custody without granting continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetainedOperationObservation {
    /// The original native completion obligation remains outstanding.
    Pending {
        /// Submission uncertainty, when positively recorded at dispatch.
        effects: Option<EffectKnowledge>,
        /// Original close disposition, including unresolved uncertainty.
        close_submission: Option<Submission>,
    },
    /// Original terminal evidence and publication obligation remain retained.
    Complete {
        /// Actual validated native result.
        outcome: Box<OperationOutcome>,
        /// Whether native custody acknowledgement completed.
        acknowledged: bool,
    },
    /// Classified effects and failed completion remain retained.
    Failed(OperationFailure),
}
