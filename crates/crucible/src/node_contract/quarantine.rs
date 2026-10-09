//! Owned whole-world containment and bounded authentic native reclamation.

use std::task::{Context, Poll};

use crucible_node_contract::Id;

use super::{NodeRuntime, RuntimePollFailure};

/// Retains a quarantined world's native handles and original effect ledger.
///
/// This owned transfer exposes no execution or semantic publication interface.
/// Cleanup failure keeps the value intact. Dropping it invokes every native
/// adapter's resource-supervision hook through the contained runtime's drop path.
#[must_use = "retain containment custody until native reclamation or supervised transfer"]
pub struct QuarantinedRuntime {
    pub(crate) runtime: NodeRuntime,
    pub(crate) cursor: Option<Id>,
}

impl QuarantinedRuntime {
    /// Polls at most one native owner's actual reclamation per invocation.
    ///
    /// `Ready(Ok(()))` means every owner has an authenticated reclamation receipt.
    /// It does not imply that original external effects were rolled back, or
    /// that the world can resume. Pending and failed polls retain native custody.
    ///
    /// # Errors
    /// Returns native cleanup failure or invalid reclamation evidence while
    /// preserving supervision and the original committed effect history.
    pub fn poll_reclamation(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), RuntimePollFailure>> {
        self.runtime
            .poll_quarantined_reclamation(&mut self.cursor, context)
    }

    /// Returns the number of owners with unresolved native resource obligations.
    pub fn remaining_owners(&self) -> usize {
        self.runtime.unreleased_owner_count()
    }

    /// Inspects original retained effects without polling or rerunning native work.
    pub fn operation(&self, operation: &Id) -> Option<super::RetainedOperationObservation> {
        self.runtime.retained_observation(operation)
    }
}
