//! Narrow non-authorizing lifecycle projections and model errors.

use aos_sandbox_core::{OperationId, Revision};

use super::{
    LifecycleMethodV1, LifecycleOperationV1, LifecyclePhaseV1, LifecycleSemanticCommitDigestV1,
    LifecycleSemanticCommitV1, LifecycleTerminalResultV1, LifecycleTimeV1,
};

/// Exposes only safe status fields for progress projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleOperationClaimV1 {
    operation_id: OperationId,
    method: LifecycleMethodV1,
    record_revision: Revision,
    phase: LifecyclePhaseV1,
    semantic_commit: Option<LifecycleSemanticCommitDigestV1>,
}

impl From<&LifecycleOperationV1> for LifecycleOperationClaimV1 {
    fn from(value: &LifecycleOperationV1) -> Self {
        Self {
            operation_id: value.operation_id(),
            method: value.intent().method(),
            record_revision: value.record_revision(),
            phase: value.phase(),
            semantic_commit: value
                .semantic_commit()
                .map(LifecycleSemanticCommitV1::witness_digest),
        }
    }
}

impl LifecycleOperationClaimV1 {
    /// Returns operation identity.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }
    /// Returns method.
    #[must_use]
    pub const fn method(self) -> LifecycleMethodV1 {
        self.method
    }
    /// Returns record revision.
    #[must_use]
    pub const fn record_revision(self) -> Revision {
        self.record_revision
    }
    /// Returns phase.
    #[must_use]
    pub const fn phase(self) -> LifecyclePhaseV1 {
        self.phase
    }
    /// Returns only semantic witness commitment.
    #[must_use]
    pub const fn semantic_commit(self) -> Option<LifecycleSemanticCommitDigestV1> {
        self.semantic_commit
    }
}

/// Exposes only the immutable terminal outcome and semantic-commit status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleTerminalProjectionV1 {
    operation_id: OperationId,
    method: LifecycleMethodV1,
    result: LifecycleTerminalResultV1,
    finished_at: LifecycleTimeV1,
    semantic_commit: Option<LifecycleSemanticCommitDigestV1>,
}

impl LifecycleOperationV1 {
    /// Returns a narrow terminal projection when the operation has one.
    #[must_use]
    pub fn terminal_projection(&self) -> Option<LifecycleTerminalProjectionV1> {
        Some(LifecycleTerminalProjectionV1 {
            operation_id: self.operation_id(),
            method: self.intent().method(),
            result: self.terminal_result()?,
            finished_at: self.finished_at()?,
            semantic_commit: self
                .semantic_commit()
                .map(LifecycleSemanticCommitV1::witness_digest),
        })
    }
}

impl LifecycleTerminalProjectionV1 {
    /// Returns operation identity.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }
    /// Returns the closed lifecycle method.
    #[must_use]
    pub const fn method(self) -> LifecycleMethodV1 {
        self.method
    }
    /// Returns terminal result.
    #[must_use]
    pub const fn result(self) -> LifecycleTerminalResultV1 {
        self.result
    }
    /// Returns terminal completion time.
    #[must_use]
    pub const fn finished_at(self) -> LifecycleTimeV1 {
        self.finished_at
    }
    /// Returns semantic-commit witness commitment, when committed.
    #[must_use]
    pub const fn semantic_commit(self) -> Option<LifecycleSemanticCommitDigestV1> {
        self.semantic_commit
    }
}

/// Reports invalid lifecycle input, transition, or encoded state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LifecycleModelError {
    /// Caller data is invalid or non-canonical.
    #[error("lifecycle model is invalid or non-canonical")]
    InvalidModel,
    /// Encoded state violates schema, bounds, or digest.
    #[error("lifecycle record encoding is corrupt")]
    CorruptEncoding,
    /// A successor violates monotone progress.
    #[error("lifecycle transition is invalid")]
    InvalidTransition,
    /// Replay conflicts with immutable intent or predecessor state.
    #[error("lifecycle history conflicts with durable state")]
    Conflict,
    /// Preflighted bounded allocation failed.
    #[error("lifecycle decode allocation failed")]
    Allocation,
}
