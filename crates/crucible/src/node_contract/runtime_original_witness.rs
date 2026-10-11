//! Restricts original collection to the retained runtime's evidence interfaces.
//!
//! An opaque collecting lifecycle can return this borrowed witness without
//! exposing an ordinary mutable runtime. It carries the same original custody
//! and current token checks, but no execution, activation or acknowledgement API.

use crucible_node_contract::{ContentRef, U64};

use super::{
    NodeRuntime, OperationToken, OriginalCompletedOperation, OriginalInputEvidence,
    OriginalInputLineageLimits, RuntimeError, RuntimePollFailure,
};
use crate::node_scheduling::InputPayload;

/// Borrows original retained operation evidence without exposing execution.
///
/// Only an actual runtime constructs this witness. It neither creates native
/// authority nor bypasses the current original token, route, codec or credit
/// checks. Source evidence readers may retain containment on uncertain readback.
pub struct OriginalRuntimeWitness<'a> {
    runtime: &'a mut NodeRuntime,
}

impl NodeRuntime {
    /// Borrows the weaker original-evidence interface of this same runtime.
    ///
    /// The returned witness cannot execute, activate, publish or acknowledge an
    /// operation, and cannot yield the underlying ordinary mutable runtime.
    pub fn original_witness(&mut self) -> OriginalRuntimeWitness<'_> {
        OriginalRuntimeWitness { runtime: self }
    }
}

impl OriginalRuntimeWitness<'_> {
    /// Borrows an actual current original permission, outcome and input custody.
    ///
    /// # Errors
    /// Refuses foreign or pending tokens, changed routes or thread scope and
    /// failed originals through the same retained runtime validation.
    pub fn original_completed_operation(
        &mut self,
        token: &OperationToken,
    ) -> Result<OriginalCompletedOperation<'_>, RuntimeError> {
        self.runtime.original_completed_operation(token)
    }

    /// Reads the complete source-selected native staging receipt closure.
    ///
    /// # Errors
    /// Refuses missing complete original stage custody, unsupported source
    /// readers, changed tokens/routes, corrupt bodies and exceeded precredits.
    pub fn original_input_evidence(
        &mut self,
        token: &OperationToken,
        limits: OriginalInputLineageLimits,
    ) -> Result<Option<OriginalInputEvidence>, RuntimePollFailure> {
        self.runtime.original_input_evidence(token, limits)
    }

    /// Reads complete original operation proof bodies under the same token.
    ///
    /// # Errors
    /// Refuses foreign, pending or failed operations, unrelated references,
    /// repeated or oversized bodies and unavailable source-authenticated bytes.
    pub fn operation_evidence(
        &mut self,
        token: &OperationToken,
        references: &[ContentRef],
        maximum_bytes: U64,
    ) -> Result<Vec<InputPayload>, RuntimePollFailure> {
        self.runtime
            .operation_evidence(token, references, maximum_bytes)
    }
}
