//! Source preparation and terminal release under the existing durable ledger.
//!
//! The preparation borrows the actual original operation; it is not recreated
//! from stored identifiers after restart. Every persistent disposition fences
//! ordinary source admission and retains the complete checkpoint. Destination
//! readiness is supplied only by the separate retained stopped-owner pairing.
//! Authenticated cross-host commit issuance remains a separate obligation.

use super::*;
use crate::{SourceTransferIntent, SourceTransferState};
use crucible_host_resources::host_supervision::{
    HostOperationClass, HostOperationGuard, HostSupervisionError,
};

/// Once-issued source preparation retaining its original operation borrow.
///
/// Dropping this value does not roll back the durable fence. A restarted
/// executor can inspect the record but cannot reconstruct this live claim.
#[must_use = "the durable source fence remains installed after this claim drops"]
pub struct SourceTransferPreparation<'original> {
    key: AttemptExecutionKey,
    source: AttemptRuntimeState,
    prepared: AttemptRuntimeState,
    original: &'original HostOperationGuard,
}

impl SourceTransferPreparation<'_> {
    /// Returns the selected whole-world checkpoint without granting execution.
    #[must_use]
    pub fn checkpoint(&self) -> Option<ExactCheckpointId> {
        self.source.checkpoint()
    }

    pub(crate) const fn binding(&self) -> (AttemptExecutionKey, AttemptRuntimeState) {
        (self.key, self.prepared)
    }
}

/// Opaque authorization required before a source release can be persisted.
///
/// Only the actual stopped receiving owner's once-issued live readiness can
/// construct this binding. Archive bytes and recovered receiving observations
/// cannot issue it. Authenticated cross-host deployment remains separate from
/// the local live-owner pairing.
pub struct SourceTransferReleaseAuthorization<'original> {
    key: AttemptExecutionKey,
    prepared: AttemptRuntimeState,
    original: &'original HostOperationGuard,
    readiness: crucible_campaign::CampaignHash,
    ownership_generation: u64,
}

impl<'original> SourceTransferReleaseAuthorization<'original> {
    pub(crate) fn from_stopped_receiver(
        source: &SourceTransferPreparation<'original>,
        ready: &crate::packaged_qemu_executor::GuardedReceivingReady,
    ) -> Option<Self> {
        let record = ready.record();
        if record.binding() != source.binding() {
            return None;
        }
        Some(Self {
            key: source.key,
            prepared: source.prepared,
            original: source.original,
            readiness: record.readiness(),
            ownership_generation: record.ownership_generation()?,
        })
    }
}

/// Reconciled durable disposition after an initiating persistence failure.
///
/// This bounded observation issues no live preparation or execution authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceTransferPersistenceOutcome {
    /// The source record still equals the exact expected pre-write state.
    SourceUnchanged,
    /// The requested fence was observed, without accepting the failed operation.
    RequestedFenceObserved,
    /// No source record was observed.
    Missing,
    /// A different state was observed and must not be interpreted as success.
    OtherState,
}

/// Typed refusal preserving an initiating persistence cause and uncertainty.
#[derive(Debug, thiserror::Error)]
pub enum SourceTransferFailure<E> {
    /// The actual borrowed original operation refused an effect boundary.
    #[error("original source transfer operation refused")]
    Original(#[source] HostSupervisionError),
    /// Loading the exact durable source state failed.
    #[error("source transfer ledger lookup failed")]
    Ledger(#[source] E),
    /// The write failed; the independently reloaded state is reported intact.
    #[error("source transfer persistence failed; durable state was reconciled")]
    Persistence {
        /// Initiating persistence cause, including committed-after-error.
        #[source]
        source: E,
        /// Current durable state; this is an observation, never authority.
        observed: SourceTransferPersistenceOutcome,
        /// Later original refusal retained without replacing the write cause.
        original: Option<HostSupervisionError>,
    },
    /// Neither a successful write nor a durable outcome could be established.
    #[error("source transfer persistence outcome is uncertain")]
    Uncertain {
        /// Initiating write cause remains the primary error source.
        #[source]
        source: E,
        /// Later lookup failure retained independently.
        reconciliation: E,
        /// Later original refusal retained independently.
        original: Option<HostSupervisionError>,
    },
    /// The original refused reconciliation after an initiating write failure.
    #[error("source transfer write failed and original reconciliation refused")]
    PersistenceOriginal {
        /// Initiating write failure remains primary.
        #[source]
        source: E,
        /// Actual refusal before any further ledger read.
        original: HostSupervisionError,
    },
    /// The exact paused execution, request or current daemon does not match.
    #[error("source transfer execution is not current")]
    NotCurrent,
    /// A worker or queued execution still owns the source incarnation.
    #[error("source transfer execution still has active ownership")]
    Active,
    /// The declaration or sealed release binding is invalid.
    #[error("source transfer binding is invalid")]
    InvalidBinding,
    /// A canceled or released source fence cannot be used for this transition.
    #[error("source transfer fence is closed")]
    Closed,
}

impl<L, V> LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    /// Fences the exact paused execution before maintenance destination work.
    ///
    /// The caller retains the existing original ledger/account owner. No new
    /// bank, clock or resource allowance is created. An existing fence cannot
    /// reissue a live claim, including after a post-write failure or restart.
    ///
    /// # Errors
    /// Refuses stale/nonsemantic/promotion-pending source preparation, active workers,
    /// invalid declaration, original cancellation/expiry, or persistence failure.
    /// A failed or uncertain write never removes the durable source fence.
    pub fn prepare_source_transfer<'original>(
        &mut self,
        key: AttemptExecutionKey,
        expected: AttemptRuntimeState,
        intent: SourceTransferIntent,
        original: &'original HostOperationGuard,
    ) -> Result<SourceTransferPreparation<'original>, SourceTransferFailure<L::Error>> {
        original
            .verify_operation_class(HostOperationClass::Transfer)
            .map_err(SourceTransferFailure::Original)?;
        let transfer =
            SourceTransferState::prepared(intent).ok_or(SourceTransferFailure::InvalidBinding)?;
        if key.scope() != AttemptExecutionScope::Semantic
            || expected.daemon_epoch() != self.daemon_epoch
            || expected.source_transfer().is_some()
        {
            return Err(SourceTransferFailure::NotCurrent);
        }
        let prepared = expected
            .with_source_transfer(transfer)
            .ok_or(SourceTransferFailure::NotCurrent)?;
        if self.active.contains_key(&expected.execution())
            || self.queued.contains(&expected.execution())
        {
            return Err(SourceTransferFailure::Active);
        }
        self.write_source_transfer(key, expected, prepared, original)?;
        Ok(SourceTransferPreparation {
            key,
            source: expected,
            prepared,
            original,
        })
    }

    /// Durably cancels preparation while preserving its non-resumable fence.
    ///
    /// # Errors
    /// Refuses a stale claim, released state, original terminal cut or failed
    /// persistence. Cancellation does not grant source or destination execution.
    pub fn cancel_source_transfer(
        &mut self,
        preparation: &SourceTransferPreparation<'_>,
    ) -> Result<(), SourceTransferFailure<L::Error>> {
        let state = preparation
            .prepared
            .source_transfer()
            .ok_or(SourceTransferFailure::InvalidBinding)?;
        let canceled = state.canceled().ok_or(SourceTransferFailure::Closed)?;
        let next = preparation
            .prepared
            .with_source_transfer(canceled)
            .ok_or(SourceTransferFailure::InvalidBinding)?;
        self.write_source_transfer(
            preparation.key,
            preparation.prepared,
            next,
            preparation.original,
        )
    }

    /// Records terminal source release from a separately sealed authorization.
    ///
    /// This method does not expose a destination world, kill a source process,
    /// retire roots, or issue an executable claim. Authorization comes only
    /// from the local live stopped-owner pairing; remote deployment remains
    /// unqualified.
    ///
    /// # Errors
    /// Refuses different original custody, exact source/request mismatch,
    /// canceled/foreign release, expired authority or uncertain persistence.
    pub fn release_source_transfer(
        &mut self,
        preparation: &SourceTransferPreparation<'_>,
        authorization: SourceTransferReleaseAuthorization<'_>,
    ) -> Result<(), SourceTransferFailure<L::Error>> {
        if authorization.key != preparation.key
            || authorization.prepared != preparation.prepared
            || !std::ptr::eq(authorization.original, preparation.original)
        {
            return Err(SourceTransferFailure::InvalidBinding);
        }
        let released = preparation
            .prepared
            .source_transfer()
            .and_then(|state| {
                state.released(authorization.readiness, authorization.ownership_generation)
            })
            .ok_or(SourceTransferFailure::InvalidBinding)?;
        let next = preparation
            .prepared
            .with_source_transfer(released)
            .ok_or(SourceTransferFailure::InvalidBinding)?;
        self.write_source_transfer(
            preparation.key,
            preparation.prepared,
            next,
            preparation.original,
        )
    }

    fn write_source_transfer(
        &mut self,
        key: AttemptExecutionKey,
        expected: AttemptRuntimeState,
        next: AttemptRuntimeState,
        original: &HostOperationGuard,
    ) -> Result<(), SourceTransferFailure<L::Error>> {
        original
            .wait_slice()
            .map_err(SourceTransferFailure::Original)?;
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(SourceTransferFailure::Ledger)?;
        // Exact repetition reports durable state; preparation itself never
        // reaches this branch because it must issue its live claim only once.
        if current == Some(next) && expected.source_transfer().is_some() {
            original
                .wait_slice()
                .map_err(SourceTransferFailure::Original)?;
            return Ok(());
        }
        if current != Some(expected) {
            return Err(SourceTransferFailure::NotCurrent);
        }
        original
            .wait_slice()
            .map_err(SourceTransferFailure::Original)?;
        let result = self
            .ledger
            .compare_exchange_attempt(key, Some(expected), Some(next));
        match result {
            Err(source) => {
                // Reconciliation cannot replace the initiating error or turn
                // a committed write into an accepting preparation claim.
                if let Err(original) = original.wait_slice() {
                    return Err(SourceTransferFailure::PersistenceOriginal { source, original });
                }
                match self.ledger.load_attempt(key) {
                    Ok(observed) => Err(SourceTransferFailure::Persistence {
                        source,
                        observed: match observed {
                            Some(state) if state == expected => {
                                SourceTransferPersistenceOutcome::SourceUnchanged
                            }
                            Some(state) if state == next => {
                                SourceTransferPersistenceOutcome::RequestedFenceObserved
                            }
                            None => SourceTransferPersistenceOutcome::Missing,
                            Some(_) => SourceTransferPersistenceOutcome::OtherState,
                        },
                        original: original.wait_slice().err(),
                    }),
                    Err(reconciliation) => Err(SourceTransferFailure::Uncertain {
                        source,
                        reconciliation,
                        original: original.wait_slice().err(),
                    }),
                }
            }
            Ok(AttemptStateCas::Conflict { .. }) => Err(SourceTransferFailure::NotCurrent),
            Ok(AttemptStateCas::Advanced) => {
                // A final original refusal leaves the durable fence installed.
                original
                    .wait_slice()
                    .map_err(SourceTransferFailure::Original)?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests;
