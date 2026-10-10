//! Borrows authenticated original terminal custody from the runtime ledger.
//!
//! This historical view binds actual local permission and terminal outcome. It
//! supplies neither native readiness nor an installed source class. Its borrow
//! prevents publication acknowledgement or replacement while an adopter checks
//! the original source window.

use super::*;

/// Borrows the runtime's actual original permission and retained terminal outcome.
///
/// Only an authentic token issued by the owning runtime can select this view.
/// It cannot be deserialized or constructed from a matching outcome DTO. Native
/// source authentication and exact producer-body association remain separate.
pub struct OriginalCompletedOperation<'a> {
    admission: &'a OperationAdmission,
    outcome: &'a OperationOutcome,
    acknowledged: bool,
    staged_inputs: Result<Option<OriginalStagedInput<'a>>, RuntimeError>,
}

impl OriginalCompletedOperation<'_> {
    /// Returns the coordinator-issued original permission, including frozen inputs.
    pub fn admission(&self) -> &OperationAdmission {
        self.admission
    }

    /// Returns the exact terminal outcome accepted and retained by the runtime.
    pub fn outcome(&self) -> &OperationOutcome {
        self.outcome
    }

    /// Reports whether the runtime retained the original publication ACK.
    ///
    /// This cached status grants no permission to acknowledge another output.
    pub fn acknowledged(&self) -> bool {
        self.acknowledged
    }

    /// Borrows complete original staging, producer lineage and ACK custody.
    ///
    /// The projection supplies historical data rather than execution permission.
    /// Existing completion accessors remain usable when this stronger witness is
    /// unavailable, including for adapters without original producer lineage.
    ///
    /// # Errors
    /// Refuses changed staging scope, unavailable native ACKs, retained failures
    /// or nonempty inputs without complete original provenance and lineage.
    pub fn staged_inputs(&self) -> Result<Option<&OriginalStagedInput<'_>>, RuntimeError> {
        self.staged_inputs
            .as_ref()
            .map(Option::as_ref)
            .map_err(Clone::clone)
    }
}

impl NodeRuntime {
    /// Borrows an authenticated original completion without servicing native work.
    ///
    /// The original permission and outcome remain owned by this runtime before
    /// and after publication acknowledgement. This method checks the current
    /// frozen route and thread scope; it performs no source-control callback,
    /// scheduler commit or publication acknowledgement.
    ///
    /// # Errors
    /// Refuses foreign tokens, changed routes or thread scope, and pending or
    /// failed operations. A changed live route retains the original containment
    /// obligation through the runtime's existing routing checks.
    pub fn original_completed_operation(
        &mut self,
        token: &OperationToken,
    ) -> Result<OriginalCompletedOperation<'_>, RuntimeError> {
        self.validate_token(token)?;
        self.checked_route(&token.route.node)?;
        let original = self
            .operations
            .get(token.operation())
            .ok_or(RuntimeError::ForeignAuthority)?;
        let (outcome, acknowledged) = match &original.result {
            RetainedResult::Complete(outcome) => (outcome, false),
            RetainedResult::Acknowledged(outcome) => (outcome, true),
            RetainedResult::Pending | RetainedResult::Failed(_) => {
                return Err(RuntimeError::OutstandingObligations);
            }
        };
        Ok(OriginalCompletedOperation {
            admission: &original.admission,
            outcome,
            acknowledged,
            staged_inputs: self.observe_original_staged_input(&original.admission),
        })
    }
}
