//! Structured graph refusals retain stage, scope, and effect certainty.

use crucible_node_contract::Id;

/// Identifies the admission stage that refused a graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionStage {
    /// Bounded local schemas and cardinality checks.
    Parse,
    /// Immutable content and installed implementation verification.
    Authenticate,
    /// Selected node, mode, and guarantee validation.
    Nodes,
    /// Endpoint, schema, capacity, and visibility validation.
    Edges,
    /// Ownership, capture closure, and causal progress validation.
    Graph,
    /// Immutable whole-world binding construction.
    Seal,
}

/// Identifies the object whose contract could not be admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionSubject {
    /// The complete world or coordinator contract.
    World,
    /// A logical public node.
    Node(Id),
    /// An indivisible execution or capture owner.
    Owner(Id),
    /// A named connection, including its endpoint contracts.
    Connection(Id),
    /// A mutable state domain.
    Domain(Id),
}

/// Records certainty about effects already performed by an admission transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectCertainty {
    /// Validation has performed no modeled or external effect.
    Absent,
    /// An identified effect is retained under authoritative custody.
    Retained,
    /// Effect completion or custody has not been established.
    Uncertain,
}

/// Names a semantic reason for refusing a requested graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionCode {
    /// The graph exceeds an admitted finite allocation or resource ceiling.
    BoundMismatch,
    /// A local core or policy schema is malformed or unsupported.
    InvalidSchema,
    /// Actual immutable content or realization differs from its binding.
    IdentityMismatch,
    /// A live claim lacks accepted evidence for its exact selected scope.
    QualificationUnavailable,
    /// A required semantic interface or feature is unknown.
    UnknownInterface,
    /// Exact protocol, schema, or selected features differ.
    FeatureMismatch,
    /// A connection does not join an output to an input.
    DirectionMismatch,
    /// Ordering, correlation, or flow-control contracts differ.
    OrderingMismatch,
    /// Selected visibility cannot satisfy the requested contract.
    VisibilityMismatch,
    /// Complete ownership or domain custody is conflicting or missing.
    OwnerConflict,
    /// The selected preservation scope cannot satisfy the requested cut.
    CaptureUnsupported,
    /// The selected replay contract cannot satisfy the requested guarantee.
    ReplayUnsupported,
    /// The scenario has not explicitly accepted the selected weaker mode.
    NondeterminismUnaccepted,
    /// A causal cycle lacks a qualified bounded same-time closure procedure.
    CausalProgressUnavailable,
    /// A positive causal bound has not been accepted for every admitted path.
    LookaheadUnproven,
}

/// Reports a side-effect-free graph validation refusal.
///
/// This validator performs no preparation or activation. Accordingly every
/// error it constructs has [`EffectCertainty::Absent`]; callers must separately
/// preserve actual preparation effects when composing a larger transaction.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{stage:?} {subject:?}: {code:?}; required {required}; observed {observed}")]
pub struct AdmissionError {
    /// Names the first failing admission stage.
    pub stage: AdmissionStage,
    /// Names the affected node, owner, domain, connection, or world.
    pub subject: AdmissionSubject,
    /// Classifies the semantic refusal.
    pub code: AdmissionCode,
    /// Describes the contract that was required.
    pub required: String,
    /// Describes the mismatch actually observed.
    pub observed: String,
    /// Records whether this validation operation has performed effects.
    pub effects: EffectCertainty,
}

pub(super) fn refuse(
    stage: AdmissionStage,
    subject: AdmissionSubject,
    code: AdmissionCode,
    required: impl Into<String>,
    observed: impl Into<String>,
) -> AdmissionError {
    AdmissionError {
        stage,
        subject,
        code,
        required: required.into(),
        observed: observed.into(),
        effects: EffectCertainty::Absent,
    }
}
