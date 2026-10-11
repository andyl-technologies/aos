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
    pub(crate) shutdown_failure: Option<super::OperationFailure>,
    pub(super) retirement_transferred: bool,
}

impl QuarantinedRuntime {
    /// Borrows the first original graceful-retirement refusal without rerunning it.
    pub fn shutdown_failure(&self) -> Option<&super::OperationFailure> {
        self.shutdown_failure.as_ref()
    }

    /// Checks an original ledger against this actually reclaimed owning capsule.
    ///
    /// Only owner lifecycle may change to Released through validated native
    /// reclamation receipts. Original activation, operations, inputs, ACKs and
    /// uncertainty remain byte-equivalent. This check grants no continuation.
    ///
    /// # Errors
    /// Refuses a lost Shutdown acknowledgement, remaining resources, changed
    /// source ledger, unsupported history or exhausted snapshot credit.
    pub fn authenticate_retired_ledger(
        &self,
        original: &super::RuntimeSnapshot,
        maximum_record_bytes: usize,
    ) -> Result<(), super::RuntimeError> {
        if self.shutdown_failure.is_some() || self.remaining_owners() != 0 {
            return Err(super::RuntimeError::OutstandingObligations);
        }
        let mut actual = self.runtime.runtime_snapshot(
            original.capture_cut,
            original.capture_ordinal,
            maximum_record_bytes,
        )?;
        if actual.owners.len() != original.owners.len() {
            return Err(super::RuntimeError::ForeignAuthority);
        }
        for (retired, saved) in actual.owners.iter_mut().zip(&original.owners) {
            if retired.identity != saved.identity
                || retired.operation != saved.operation
                || retired.domains != saved.domains
                || retired.lifecycle != super::Lifecycle::Released
            {
                return Err(super::RuntimeError::InvalidReceipt);
            }
            retired.lifecycle = saved.lifecycle;
        }
        if actual != *original {
            return Err(super::RuntimeError::InvalidReceipt);
        }
        Ok(())
    }

    /// Moves reclaimed original native handles while retaining this full runtime.
    ///
    /// Host models, original ledgers and this custody slot stay owned. Each
    /// adapter's original supervisor remains charged; this grants no release.
    /// Retrying a partial transfer inspects the same original adapter state.
    ///
    /// # Errors
    /// Refuses non-graceful custody, uncertain Shutdown, remaining resources or
    /// an unsupported actual adapter. A refusal retains the same whole capsule.
    pub fn transfer_retirement_resources(&mut self) -> Result<(), super::RuntimeError> {
        if !self.runtime.graceful_retirement
            || self.shutdown_failure.is_some()
            || self.remaining_owners() != 0
        {
            return Err(super::RuntimeError::OutstandingObligations);
        }
        self.runtime.transfer_reclaimed_adapters()?;
        self.retirement_transferred = true;
        Ok(())
    }

    /// Reads actual retained models and histories after graceful resource retirement.
    ///
    /// Physical reaping does not replace original modeled history. This reader
    /// uses the same owning runtime and adapter capsules and grants no release.
    ///
    /// # Errors
    /// Refuses unsupported complete history or exhausted prebirth body credit.
    pub fn retirement_histories(
        &self,
        activation: &super::WorldActivation,
        maximum_total_bytes: usize,
    ) -> Result<Vec<super::RetainedRetirementHistory>, super::RuntimeError> {
        self.runtime
            .retirement_histories(activation, maximum_total_bytes)
    }

    /// Reconciles original publication while retaining complete native containment.
    ///
    /// This updates durable disposition without issuing an activation token or
    /// releasing resources. Even committed worlds remain quarantined.
    ///
    /// # Errors
    /// Refuses foreign records or publication that was not uncertain.
    pub fn reconcile_publication(
        &mut self,
        record: &super::ActivationRecord,
        publisher: &mut dyn super::ActivationPublisher,
    ) -> Result<super::PublicationStatus, super::RuntimeError> {
        self.runtime
            .reconcile_contained_publication(record, publisher)
    }

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
