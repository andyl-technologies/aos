//! Tracks prepared views separately from owning successful history completion.

use std::collections::BTreeMap;

use terrane_core::gc::publication::evidence::ConsumedViewInterpretation;
use terrane_core::identity::Digest;

use crate::guard::history::CompletedViewUse;
use crate::guard::history::completion::PendingViewUse;
use crate::guard::invalid;
use crate::store::StoreFailure;

/// Retains exact operation-local preparation and completed producer results.
#[derive(Clone, Default)]
pub(super) struct ViewContextTrace {
    pending: BTreeMap<Digest, PendingViewUse>,
    completed: BTreeMap<Digest, PendingViewUse>,
}

impl ViewContextTrace {
    /// Records prepared data without promoting it to completed evidence.
    ///
    /// # Errors
    /// Rejects a contradictory repeated preparation or completed view.
    pub(super) fn pending(&mut self, prepared: &PendingViewUse) -> Result<(), StoreFailure> {
        let identity = prepared.context().view;
        if let Some(completed) = self.completed.get(&identity) {
            return if completed == prepared {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if self
            .pending
            .get(&identity)
            .is_some_and(|old| old != prepared)
        {
            return Err(invalid());
        }
        self.pending.insert(identity, prepared.clone());
        Ok(())
    }

    /// Consumes only a result privately produced after full history success.
    ///
    /// # Errors
    /// Rejects an absent or contradictory preparation or completed view.
    pub(super) fn complete(&mut self, completed: &CompletedViewUse) -> Result<(), StoreFailure> {
        let prepared = completed.prepared();
        let identity = prepared.context().view;
        if let Some(old) = self.completed.get(&identity) {
            return if old == prepared {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if self.pending.get(&identity) != Some(prepared) {
            return Err(invalid());
        }
        self.pending.remove(&identity);
        self.completed.insert(identity, prepared.clone());
        Ok(())
    }

    /// Observes actual completed map rows without accepting producer evidence.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(super) fn observed_completed(&self) -> Vec<ConsumedViewInterpretation> {
        self.completed
            .values()
            .map(|view| view.context().clone())
            .collect()
    }

    /// Serializes completed contexts only after all pending views are resolved.
    ///
    /// # Errors
    /// Rejects unresolved preparations. Absence never selects Legacy.
    pub(super) fn finish(&self) -> Result<Vec<ConsumedViewInterpretation>, StoreFailure> {
        if !self.pending.is_empty() {
            return Err(invalid());
        }
        Ok(self
            .completed
            .values()
            .map(|view| view.context().clone())
            .collect())
    }
}
