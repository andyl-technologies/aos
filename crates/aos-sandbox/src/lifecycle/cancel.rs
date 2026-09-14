//! Version-fenced, idempotent cancellation admission for lifecycle operations.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, OperationId, PrincipalId, ProjectId, Revision};
use sha2::{Digest as _, Sha256};

use super::{
    encode_operation_record_v1, LifecycleMethodSemanticCommitV1, LifecycleModelError,
    LifecycleOperationV1, LifecycleRecordDigestV1, LifecycleTerminalResultV1, LifecycleTimeV1,
};

/// Maximum cancellation keys retained by one replay checkpoint.
pub const MAXIMUM_LIFECYCLE_CANCEL_BINDINGS: usize = 262_144;

/// Commits a cancellation idempotency key in its own purpose domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LifecycleCancelIdempotencyDigestV1(ObjectDigest);

impl LifecycleCancelIdempotencyDigestV1 {
    /// Commits exact cancellation-key bytes.
    #[must_use]
    pub fn commit(bytes: &[u8]) -> Self {
        Self(ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.cancel-idempotency.v1\0")
                .chain_update(bytes)
                .finalize()
                .into(),
        ))
    }

    /// Returns the underlying SHA-256 commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }

    pub(super) fn from_stored(value: ObjectDigest) -> Result<Self, LifecycleModelError> {
        if value.as_bytes() == &[0; 32] {
            Err(LifecycleModelError::CorruptEncoding)
        } else {
            Ok(Self(value))
        }
    }
}

/// Selects an exact operation record for a cancellation race.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleCancelRequestV1 {
    caller: PrincipalId,
    project: ProjectId,
    operation_id: OperationId,
    expected_revision: Revision,
    expected_record: LifecycleRecordDigestV1,
    idempotency: LifecycleCancelIdempotencyDigestV1,
    requested_at: LifecycleTimeV1,
}

impl LifecycleCancelRequestV1 {
    /// Constructs a version-fenced cancellation admission request.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for sentinel identity or revision.
    pub fn new(
        caller: PrincipalId,
        project: ProjectId,
        operation_id: OperationId,
        expected_revision: Revision,
        expected_record: LifecycleRecordDigestV1,
        idempotency: LifecycleCancelIdempotencyDigestV1,
        requested_at: LifecycleTimeV1,
    ) -> Result<Self, LifecycleModelError> {
        if caller.as_bytes() == &[0; 16]
            || project.as_bytes() == &[0; 16]
            || operation_id.as_bytes() == &[0; 16]
            || expected_revision.get() == 0
            || expected_revision.get() == u64::MAX
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            caller,
            project,
            operation_id,
            expected_revision,
            expected_record,
            idempotency,
            requested_at,
        })
    }

    /// Returns the authenticated cancellation caller.
    #[must_use]
    pub const fn caller(self) -> PrincipalId {
        self.caller
    }

    /// Returns the project authority scope.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the target operation identity.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }
    /// Returns the exact expected record revision.
    #[must_use]
    pub const fn expected_revision(self) -> Revision {
        self.expected_revision
    }
    /// Returns the exact expected canonical record commitment.
    #[must_use]
    pub const fn expected_record(self) -> LifecycleRecordDigestV1 {
        self.expected_record
    }
    /// Returns the independent cancellation idempotency commitment.
    #[must_use]
    pub const fn idempotency(self) -> LifecycleCancelIdempotencyDigestV1 {
        self.idempotency
    }
    /// Returns the cancellation admission time.
    #[must_use]
    pub const fn requested_at(self) -> LifecycleTimeV1 {
        self.requested_at
    }
}

/// Classifies the exact cancel-versus-commit race without mutating the operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleCancelOutcomeV1 {
    /// The version fence won and this exact operation successor must be journaled atomically.
    CanceledBeforeCommit(LifecycleOperationV1),
    /// Semantic commit won and its complete durable witness is retained.
    AlreadyCommitted(LifecycleMethodSemanticCommitV1),
    /// A pre-commit terminal outcome was already durable.
    AlreadyTerminal(LifecycleTerminalResultV1),
    /// The operation identity, revision, or record digest no longer matches.
    Conflict,
}

/// Stores one stable cancellation-idempotency resolution with its operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleCancellationRecordV1 {
    request: LifecycleCancelRequestV1,
    operation: LifecycleOperationV1,
    outcome: LifecycleCancelOutcomeV1,
}

impl LifecycleCancellationRecordV1 {
    /// Constructs a reconstructing durable cancellation resolution.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] if the retained operation
    /// does not prove the selected stable cancel-versus-commit outcome.
    pub fn new(
        request: LifecycleCancelRequestV1,
        operation: LifecycleOperationV1,
        outcome: LifecycleCancelOutcomeV1,
    ) -> Result<Self, LifecycleModelError> {
        let operation_matches = request.operation_id() == operation.operation_id()
            && request.project() == operation.project()
            && request.requested_at() >= operation.accepted_at();
        let outcome_matches = match &outcome {
            LifecycleCancelOutcomeV1::CanceledBeforeCommit(successor) => {
                successor == &operation
                    && successor.predecessor_digest() == Some(request.expected_record())
                    && request
                        .expected_revision()
                        .checked_next()
                        .is_ok_and(|revision| revision == successor.record_revision())
                    && operation.method_semantic_commit().is_none()
                    && matches!(
                        operation.phase(),
                        super::LifecyclePhaseV1::Compensating | super::LifecyclePhaseV1::Terminal
                    )
            }
            LifecycleCancelOutcomeV1::AlreadyCommitted(commit) => {
                operation.record_revision() == request.expected_revision()
                    && super::format::record_digest(&encode_operation_record_v1(&operation)?)?
                        == request.expected_record()
                    && operation.method_semantic_commit() == Some(commit)
            }
            LifecycleCancelOutcomeV1::AlreadyTerminal(terminal) => {
                operation.record_revision() == request.expected_revision()
                    && super::format::record_digest(&encode_operation_record_v1(&operation)?)?
                        == request.expected_record()
                    && operation.terminal_result() == Some(*terminal)
            }
            LifecycleCancelOutcomeV1::Conflict => false,
        };
        if !operation_matches || !outcome_matches {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            request,
            operation,
            outcome,
        })
    }

    /// Returns the exact cancellation request binding.
    #[must_use]
    pub const fn request(&self) -> LifecycleCancelRequestV1 {
        self.request
    }

    /// Borrows the exact operation proving the stable outcome.
    #[must_use]
    pub const fn operation(&self) -> &LifecycleOperationV1 {
        &self.operation
    }

    /// Borrows the stable cancellation resolution.
    #[must_use]
    pub const fn outcome(&self) -> &LifecycleCancelOutcomeV1 {
        &self.outcome
    }
}

/// Resolves an exact cancellation race against one replay-validated record.
///
/// The record fence is checked first. At that exact version semantic commit
/// wins over cancellation, and an existing terminal outcome wins over a new
/// cancellation. The result carries no authority to compensate effects.
pub(super) fn resolve_cancel_operation_v1(
    request: LifecycleCancelRequestV1,
    operation: &LifecycleOperationV1,
    current_record: LifecycleRecordDigestV1,
) -> LifecycleCancelOutcomeV1 {
    if request.operation_id() != operation.operation_id()
        || request.project() != operation.project()
        || request.expected_revision() != operation.record_revision()
        || request.expected_record() != current_record
        || request.requested_at() < operation.accepted_at()
    {
        return LifecycleCancelOutcomeV1::Conflict;
    }
    if let Some(commit) = operation.method_semantic_commit() {
        LifecycleCancelOutcomeV1::AlreadyCommitted(commit.clone())
    } else if let Some(terminal) = operation.terminal_result() {
        LifecycleCancelOutcomeV1::AlreadyTerminal(terminal)
    } else {
        // Ambiguous effects still require reconciliation. A known failed
        // reverse compensation starts.
        if operation.steps().iter().any(|step| {
            matches!(
                step.state(),
                super::LifecycleStepStateV1::Applying | super::LifecycleStepStateV1::Compensating
            )
        }) {
            return LifecycleCancelOutcomeV1::Conflict;
        }
        let mut steps = Vec::new();
        if steps.try_reserve_exact(operation.steps().len()).is_err() {
            return LifecycleCancelOutcomeV1::Conflict;
        }
        steps.extend_from_slice(operation.steps());
        for step in &mut steps {
            if step.state() == super::LifecycleStepStateV1::Residual {
                let Ok(canceled) = step.cancel_retryable_forward() else {
                    return LifecycleCancelOutcomeV1::Conflict;
                };
                *step = canceled;
            }
        }
        let no_effects_applied = operation.forward_progress() == 0
            && steps.iter().all(|step| {
                matches!(
                    step.state(),
                    super::LifecycleStepStateV1::Planned | super::LifecycleStepStateV1::Canceled
                )
            });
        let successor = operation.successor(
            current_record,
            if no_effects_applied {
                super::LifecyclePhaseV1::Terminal
            } else {
                super::LifecyclePhaseV1::Compensating
            },
            operation.forward_progress(),
            operation.compensation_progress(),
            steps,
            None,
            None,
            None,
            no_effects_applied.then_some(LifecycleTerminalResultV1::CanceledBeforeCommit),
            no_effects_applied.then_some(request.requested_at()),
        );
        match successor {
            Ok(successor) => LifecycleCancelOutcomeV1::CanceledBeforeCommit(successor),
            Err(_) => LifecycleCancelOutcomeV1::Conflict,
        }
    }
}

/// Retains durable cancellation-idempotency resolutions by authority scope.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LifecycleCancelIdempotencyIndexV1 {
    bindings: BTreeMap<
        (PrincipalId, ProjectId, LifecycleCancelIdempotencyDigestV1),
        (LifecycleCancelRequestV1, LifecycleCancelOutcomeV1),
    >,
}

impl LifecycleCancelIdempotencyIndexV1 {
    pub(super) fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Commits every sorted cancellation request and stable race outcome.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError`] if an operation outcome cannot be
    /// canonically encoded within its fixed ceiling.
    pub fn complete_digest(&self) -> Result<ObjectDigest, LifecycleModelError> {
        let mut hasher = Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.cancel-index.v1\0")
            .chain_update((self.bindings.len() as u64).to_be_bytes());
        for ((caller, project, key), (request, outcome)) in &self.bindings {
            hasher = hasher
                .chain_update(caller.as_bytes())
                .chain_update(project.as_bytes())
                .chain_update(key.digest().as_bytes())
                .chain_update(request.operation_id().as_bytes())
                .chain_update(request.expected_revision().get().to_be_bytes())
                .chain_update(request.expected_record().digest().as_bytes())
                .chain_update(request.requested_at().get().to_be_bytes());
            match outcome {
                LifecycleCancelOutcomeV1::CanceledBeforeCommit(operation) => {
                    let encoded = super::encode_operation_record_v1(operation)?;
                    hasher = hasher
                        .chain_update([1])
                        .chain_update((encoded.len() as u64).to_be_bytes())
                        .chain_update(encoded);
                }
                LifecycleCancelOutcomeV1::AlreadyCommitted(commit) => {
                    hasher = hasher
                        .chain_update([2])
                        .chain_update(commit.complete_digest().digest().as_bytes());
                }
                LifecycleCancelOutcomeV1::AlreadyTerminal(terminal) => {
                    hasher = hasher.chain_update([3, *terminal as u8]);
                }
                LifecycleCancelOutcomeV1::Conflict => {
                    hasher = hasher.chain_update([4]);
                }
            }
        }
        Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
    }

    pub(super) fn lookup(
        &self,
        request: LifecycleCancelRequestV1,
    ) -> Option<LifecycleCancelOutcomeV1> {
        let key = (request.caller(), request.project(), request.idempotency());
        self.bindings.get(&key).map(|(bound_request, outcome)| {
            if *bound_request == request {
                outcome.clone()
            } else {
                LifecycleCancelOutcomeV1::Conflict
            }
        })
    }

    /// Resolves and durably indexes one exact cancellation request.
    ///
    /// An exact duplicate returns its original outcome. Reuse of a key with a
    /// different target or fence fails closed as [`LifecycleCancelOutcomeV1::Conflict`].
    pub(super) fn resolve(
        &mut self,
        request: LifecycleCancelRequestV1,
        operation: &LifecycleOperationV1,
        current_record: LifecycleRecordDigestV1,
    ) -> LifecycleCancelOutcomeV1 {
        if let Some(outcome) = self.lookup(request) {
            return outcome;
        }
        let key = (request.caller(), request.project(), request.idempotency());
        if self.bindings.len() >= MAXIMUM_LIFECYCLE_CANCEL_BINDINGS {
            return LifecycleCancelOutcomeV1::Conflict;
        }
        let outcome = resolve_cancel_operation_v1(request, operation, current_record);
        // A conflict can be transient while an ambiguous attempt is being
        // reconciled. Only stable race outcomes consume the idempotency key.
        if outcome != LifecycleCancelOutcomeV1::Conflict {
            self.bindings.insert(key, (request, outcome.clone()));
        }
        outcome
    }

    /// Applies one decoded stable cancellation binding during replay.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidTransition`] for a divergent
    /// duplicate or when the bounded index is full.
    pub fn apply_record(
        &mut self,
        record: &LifecycleCancellationRecordV1,
    ) -> Result<(), LifecycleModelError> {
        let request = record.request();
        let key = (request.caller(), request.project(), request.idempotency());
        let binding = (request, record.outcome().clone());
        if let Some(existing) = self.bindings.get(&key) {
            return if existing == &binding {
                Ok(())
            } else {
                Err(LifecycleModelError::InvalidTransition)
            };
        }
        if self.bindings.len() >= MAXIMUM_LIFECYCLE_CANCEL_BINDINGS {
            return Err(LifecycleModelError::InvalidTransition);
        }
        self.bindings.insert(key, binding);
        Ok(())
    }
}
