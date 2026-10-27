//! Retains finite data-only refusals without creating native lanes or threads.
//!
//! Every entry comes from the ledger's original lifetime reservation. Exact
//! request bytes remain rooted by that durable reservation; this queue retains
//! its original completion authority and identical sealed result across errors.
//! It never constructs a catalog, prepares a node, or grants redispatch.

#[cfg(test)]
mod tests;

use super::super::CapabilityPreparationState;
use super::super::ledger::{
    CapabilityPreparationLedger, CapabilityReservation, MAXIMUM_RECORDS, SealedCompletion,
};
use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
};

/// Retains original data-only completion custody through fallible placement.
pub(in crate::node_observed_executor::service) struct Refusal {
    reservation: CapabilityReservation,
    ledger: CapabilityPreparationLedger,
    sealed: Option<SealedCompletion>,
    completed: bool,
}

impl Refusal {
    /// Retains the original reservation without preparing native ownership.
    pub(super) fn new(
        reservation: CapabilityReservation,
        ledger: CapabilityPreparationLedger,
    ) -> Self {
        Self {
            reservation,
            ledger,
            sealed: None,
            completed: false,
        }
    }

    /// Polls the same original completion without surrendering it on unwind.
    pub(super) fn poll(&mut self) -> bool {
        catch_unwind(AssertUnwindSafe(|| self.reconcile())).unwrap_or(false)
    }

    fn reconcile(&mut self) -> bool {
        if self.sealed.is_none() {
            self.sealed = self
                .ledger
                .seal_completion(
                    &self.reservation,
                    CapabilityPreparationState::Unavailable {
                        reason: "native world capacity or original ownership unavailable".into(),
                    },
                )
                .ok();
        }

        self.sealed.as_ref().is_some_and(|sealed| {
            self.ledger
                .place_completion(&self.reservation, sealed)
                .is_ok()
        })
    }
}

/// Bounds independent data-only terminal reconciliation by lifetime debit.
pub(super) struct Refusals {
    originals: BTreeMap<String, Refusal>,
    maximum: usize,
    cursor: Option<String>,
}

impl Refusals {
    /// Creates an empty mailbox under the ledger's original request ceiling.
    pub(super) fn new() -> Self {
        Self {
            originals: BTreeMap::new(),
            maximum: MAXIMUM_RECORDS,
            cursor: None,
        }
    }

    /// Returns the number of original refusals still requiring placement.
    pub(super) fn len(&self) -> usize {
        self.originals.len()
    }

    /// Moves only a credited unique original; refusal leaves the caller owning it.
    pub(super) fn retain_original(&mut self, incoming: &mut Option<Refusal>) {
        let Some(original) = incoming.as_ref() else {
            return;
        };
        if self.originals.len() >= self.maximum
            || !original.reservation.original_dispatch
            || !matches!(
                original.reservation.record.outcome,
                CapabilityPreparationState::AwaitingAdmission {}
            )
            || self
                .originals
                .contains_key(&original.reservation.record.execution)
        {
            return;
        }

        // The same source constant bounds the ledger's prior lifetime debit and
        // this separate no-native mailbox. Admission is checked before insertion.
        let execution = original.reservation.record.execution.clone();
        if let Some(original) = incoming.take() {
            self.originals.insert(execution, original);
        }
    }

    /// Attempts one cursor-selected original, keeping failures for a later turn.
    ///
    /// Backend callbacks are synchronous and may individually block. This bounds
    /// attempted originals per actor turn, not individual storage latency.
    pub(super) fn poll(&mut self) -> bool {
        use std::ops::Bound::{Excluded, Unbounded};

        let next = self.cursor.as_ref().and_then(|cursor| {
            self.originals
                .range((Excluded(cursor.clone()), Unbounded))
                .next()
                .map(|(execution, _)| execution.clone())
        });
        let next = next.or_else(|| self.originals.keys().next().cloned());
        let Some(execution) = next else {
            return false;
        };
        self.cursor = Some(execution.clone());

        if let Some(original) = self.originals.get_mut(&execution) {
            original.completed = original.poll();
            if original.completed {
                self.originals.remove(&execution);
            }
        }
        true
    }
}
