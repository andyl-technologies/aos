//! Durable caller/project/method idempotency bindings for lifecycle admission.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, OperationId, PrincipalId, ProjectId};
use sha2::{Digest as _, Sha256};

use super::{
    LifecycleIdempotencyDigestV1, LifecycleMethodSemanticCommitDigestV1, LifecycleMethodV1,
    LifecycleNormalizedRequestDigestV1, LifecycleOperationV1, LifecycleTerminalResultV1,
};

/// Maximum durable admission keys retained by one materialized history.
pub const MAXIMUM_LIFECYCLE_IDEMPOTENCY_BINDINGS: usize = 262_144;

/// Selects the exact authority and method namespace of an idempotency key.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleIdempotencyScopeV1 {
    caller: PrincipalId,
    project: ProjectId,
    method: LifecycleMethodV1,
}

impl LifecycleIdempotencyScopeV1 {
    /// Constructs the scope captured by a validated operation.
    #[must_use]
    pub const fn from_operation(operation: &LifecycleOperationV1) -> Self {
        Self {
            caller: operation.caller(),
            project: operation.project(),
            method: operation.intent().method(),
        }
    }

    /// Returns the authenticated caller identity.
    #[must_use]
    pub const fn caller(self) -> PrincipalId {
        self.caller
    }

    /// Returns the project authority scope.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the closed lifecycle method.
    #[must_use]
    pub const fn method(self) -> LifecycleMethodV1 {
        self.method
    }
}

/// Retains the immutable request binding and current durable outcome witnesses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleIdempotencyBindingV1 {
    normalized_request: LifecycleNormalizedRequestDigestV1,
    operation_id: OperationId,
    terminal: Option<LifecycleTerminalResultV1>,
    semantic_commit: Option<LifecycleMethodSemanticCommitDigestV1>,
}

impl LifecycleIdempotencyBindingV1 {
    /// Returns the exact normalized request commitment.
    #[must_use]
    pub const fn normalized_request(self) -> LifecycleNormalizedRequestDigestV1 {
        self.normalized_request
    }

    /// Returns the first admitted operation identity.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Returns the current terminal outcome, when one is durable.
    #[must_use]
    pub const fn terminal(self) -> Option<LifecycleTerminalResultV1> {
        self.terminal
    }

    /// Returns the retained irreversible semantic-commit witness.
    #[must_use]
    pub const fn semantic_commit(self) -> Option<LifecycleMethodSemanticCommitDigestV1> {
        self.semantic_commit
    }
}

/// Classifies a key lookup without admitting or authorizing an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleIdempotencyResolutionV1 {
    /// No durable binding exists for this exact scope and key.
    Unbound,
    /// The exact request is already bound to the returned original operation.
    Existing(LifecycleIdempotencyBindingV1),
    /// The key is durably bound to a different normalized request.
    Divergent(LifecycleIdempotencyBindingV1),
}

/// Maintains bounded replay-derived idempotency bindings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LifecycleIdempotencyIndexV1 {
    bindings: BTreeMap<
        (LifecycleIdempotencyScopeV1, LifecycleIdempotencyDigestV1),
        LifecycleIdempotencyBindingV1,
    >,
}

impl LifecycleIdempotencyIndexV1 {
    /// Commits every sorted authority/key/request/outcome binding.
    #[must_use]
    pub fn complete_digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.idempotency-index.v1\0")
            .chain_update((self.bindings.len() as u64).to_be_bytes());
        for ((scope, key), binding) in &self.bindings {
            hasher = hasher
                .chain_update(scope.caller().as_bytes())
                .chain_update(scope.project().as_bytes())
                .chain_update([scope.method() as u8])
                .chain_update(key.digest().as_bytes())
                .chain_update(binding.normalized_request().digest().as_bytes())
                .chain_update(binding.operation_id().as_bytes())
                .chain_update([binding.terminal().map_or(0, |value| value as u8)])
                .chain_update(
                    binding
                        .semantic_commit()
                        .map_or(ObjectDigest::from_bytes([0; 32]), |value| value.digest())
                        .as_bytes(),
                );
        }
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    /// Resolves an exact key/request pair to its original durable operation.
    #[must_use]
    pub fn resolve(
        &self,
        scope: LifecycleIdempotencyScopeV1,
        key: LifecycleIdempotencyDigestV1,
        request: LifecycleNormalizedRequestDigestV1,
    ) -> LifecycleIdempotencyResolutionV1 {
        match self.bindings.get(&(scope, key)).copied() {
            None => LifecycleIdempotencyResolutionV1::Unbound,
            Some(binding) if binding.normalized_request == request => {
                LifecycleIdempotencyResolutionV1::Existing(binding)
            }
            Some(binding) => LifecycleIdempotencyResolutionV1::Divergent(binding),
        }
    }

    pub(super) fn observe(&mut self, operation: &LifecycleOperationV1) -> Result<(), ()> {
        let scope = LifecycleIdempotencyScopeV1::from_operation(operation);
        let key = (scope, operation.idempotency());
        let semantic_commit = operation
            .method_semantic_commit()
            .map(|witness| witness.complete_digest());
        match self.bindings.get_mut(&key) {
            None => {
                if self.bindings.len() >= MAXIMUM_LIFECYCLE_IDEMPOTENCY_BINDINGS {
                    return Err(());
                }
                self.bindings.insert(
                    key,
                    LifecycleIdempotencyBindingV1 {
                        normalized_request: operation.normalized_request(),
                        operation_id: operation.operation_id(),
                        terminal: operation.terminal_result(),
                        semantic_commit,
                    },
                );
            }
            Some(binding)
                if binding.normalized_request == operation.normalized_request()
                    && binding.operation_id == operation.operation_id()
                    && binding
                        .semantic_commit
                        .is_none_or(|old| semantic_commit == Some(old))
                    && binding
                        .terminal
                        .is_none_or(|old| operation.terminal_result() == Some(old)) =>
            {
                binding.semantic_commit = semantic_commit;
                binding.terminal = operation.terminal_result();
            }
            Some(_) => return Err(()),
        }
        Ok(())
    }
}
