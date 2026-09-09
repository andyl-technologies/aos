//! Structured diagnostics shared by validators, planners, and frontends.

use serde::{Deserialize, Serialize};

use crate::identity::{RequestId, ResourceId, ScopedOperationKey};

/// Classifies a contract, planning, or execution failure.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticClass {
    /// A document or graph violates its closed semantic contract.
    InvalidContract,
    /// An interface identity or promised semantic is incompatible.
    IncompatibleInterface,
    /// A caller or provider lacks the required grant.
    Unauthorized,
    /// Multiple eligible providers remain without an explicit policy choice.
    AmbiguousBinding,
    /// A required external deployment input remains unresolved.
    UnsatisfiedObligation,
    /// Resource ownership, scope, or access conflicts.
    ResourceConflict,
    /// A current revision or assignment differs from a required precondition.
    StalePrecondition,
    /// A selected or planned provider cannot be acquired.
    UnavailableProvider,
    /// A finite attempt or recovery budget expired.
    DeadlineExceeded,
    /// An external effect may have occurred but is not yet reconciled.
    IndeterminateEffect,
    /// Durable recovery evidence is invalid or unsupported.
    CorruptRecoveryState,
}

/// Identifies the validation or execution phase reporting a diagnostic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticPhase {
    /// Applies before a typed document is constructed.
    Decode,
    /// Applies while checking a portable value schema.
    Schema,
    /// Applies while checking provider bindings and grants.
    Binding,
    /// Applies while checking the finite operation graph.
    Planning,
    /// Applies while acquiring fresh runtime authority.
    Admission,
    /// Applies while an admitted operation runs.
    Execution,
    /// Applies while reconciling durable transaction state.
    Recovery,
}

/// Gives a stable machine-readable meaning to a diagnostic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticCode {
    /// The schema discriminator does not match the selected format.
    UnsupportedSchema,
    /// A required format feature is unknown to the validator.
    UnsupportedRequiredFeature,
    /// A document or graph exceeds an effective versioned limit.
    LimitExceeded,
    /// A semantically unordered list is not in canonical order.
    NonCanonicalOrder,
    /// A stable identifier appears more than once.
    DuplicateIdentity,
    /// A reference names no authenticated graph object.
    MissingReference,
    /// A value does not satisfy its closed schema.
    ValueTypeMismatch,
    /// A result is consumed before its declared availability phase.
    ResultPhaseMismatch,
    /// A result reference lacks the required typed data edge.
    MissingDataDependency,
    /// Scheduling dependencies contain a cycle.
    SchedulingCycle,
    /// A changed mutable resource has no lifecycle controller.
    MissingController,
    /// More than one lifecycle controller claims one resource.
    ConflictingController,
    /// A changed resource has no realizing write or explicit obligation.
    UncoveredChange,
    /// A resource access exceeds the selected authority grant.
    ResourceScopeEscape,
    /// An invocation calls a method outside its grant.
    MethodNotGranted,
    /// Provider implementation authority is used without mediation permission.
    MediationNotGranted,
    /// A binding supplies fewer guarantees than its request requires.
    MissingGuarantee,
    /// An invocation's method or family disagrees with its exact descriptor.
    MethodContractMismatch,
    /// A binding points at an interface the request did not accept.
    BindingInterfaceMismatch,
    /// A binding's principal does not match its request or provider.
    BindingPrincipalMismatch,
    /// An unresolved deployment obligation prevents execution.
    UnresolvedObligation,
}

/// Describes one precise failure without requiring frontends to parse prose.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    /// Supplies the stable machine-readable condition.
    pub code: DiagnosticCode,
    /// Classifies the broader failure behavior.
    pub class: DiagnosticClass,
    /// Identifies the checking or execution phase.
    pub phase: DiagnosticPhase,
    /// Identifies the field or graph element using JSON-pointer components.
    pub path: Vec<String>,
    /// Provides a bounded human-facing explanation.
    pub message: String,
    /// Identifies the originating request, when applicable.
    pub request: Option<RequestId>,
    /// Identifies the related operation, when applicable.
    pub operation: Option<ScopedOperationKey>,
    /// Identifies the related resource, when applicable.
    pub resource: Option<ResourceId>,
    /// States whether a live external effect may already have occurred.
    pub live_effect_may_have_occurred: bool,
}
