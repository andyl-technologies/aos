//! Owns invocation-local native completion of immutable historical verification.
//!
//! Overlay verification has no token, current-ref permission or mutation purpose.
//! Each invocation borrows its actual held scope, walks the full history and closes recipes
//! before promoting contextual view inputs. The target may be a historical view.

use super::{Guard, HistoryObservation, OriginalAuthority, RetainedControls, invalid};
use crate::bucket::publication::SelectedObservation;
use crate::store::{Clock, Store, StoreFailure};
use std::collections::BTreeMap;
use std::sync::Arc;
use terrane_format::gc::publication::evidence::RequiredControlPin;
use terrane_format::identity::Digest;
use terrane_format::provenance::VerifiedHistory;

mod inputs;
mod store;

pub(crate) use inputs::CheckedOverlayHistoryInputs;
pub(in crate::guard) use store::OverlayHistoryStore;

#[cfg(test)]
mod tests;

/// Retains actual Original registration inputs and one private read identity.
///
/// This carrier grants no token permission. Its inventory checks precede and
/// follow the independent native closing of all original physical recipes.
#[derive(Clone)]
pub(crate) struct OverlayReadCheck {
    inputs: Arc<OverlayInputs>,
}

struct OverlayInputs {
    target: Digest,
    registration: RequiredControlPin,
    controls: RetainedControls,
}

impl OverlayReadCheck {
    /// Captures an actual checked registration under its genuine control hold.
    ///
    /// # Errors
    /// Refuses another authority, missing records or inconsistent retained pins.
    pub(in crate::guard) fn capture(
        target: Digest,
        authority: &OriginalAuthority,
        registration: RequiredControlPin,
        controls: RetainedControls,
    ) -> Result<Self, StoreFailure> {
        if registration.owner != super::consumed_registration(authority)
            || controls.directory() != authority.control()
        {
            return Err(invalid());
        }
        let check = Self {
            inputs: Arc::new(OverlayInputs {
                target,
                registration,
                controls,
            }),
        };
        check.recheck()?;
        Ok(check)
    }

    /// Checks the exact retained registration inventory without granting rights.
    ///
    /// Physical freshness comes from the original record recipes, closed by the
    /// native worker under the same retained namespace and control exclusions.
    ///
    /// # Errors
    /// Refuses missing or contradictory original canonical registration bytes.
    pub(crate) fn recheck(&self) -> Result<(), StoreFailure> {
        let pin = &self.inputs.registration;
        let record = self
            .inputs
            .controls
            .records()
            .iter()
            .find(|record| record.path() == self.inputs.controls.directory().join(&pin.key))
            .ok_or_else(invalid)?;
        pin.check_record(record.bytes()).map_err(|_| invalid())
    }

    /// Requires this exact captured overlay invocation, including its real holds.
    ///
    /// # Errors
    /// Refuses another invocation even when the target and record bytes match.
    pub(crate) fn same_invocation(&self, other: &Self) -> Result<(), StoreFailure> {
        if !Arc::ptr_eq(&self.inputs, &other.inputs) {
            return Err(invalid());
        }
        self.recheck()
    }
}

/// Binds an immutable target independently from the actual selected backend head.
pub(crate) struct OverlayPurpose<'history, 'held> {
    target: Digest,
    observation: HistoryObservation<'history>,
    selected: &'history SelectedObservation<'held>,
    check: OverlayReadCheck,
}

impl<'history, 'held> OverlayPurpose<'history, 'held> {
    /// Binds the genuine overlay invocation to its original captured selection.
    ///
    /// # Errors
    /// Refuses foreign holders, operation purposes or unrelated target inputs.
    pub(in crate::guard) fn capture(
        target: Digest,
        selected: &'history SelectedObservation<'held>,
        observation: HistoryObservation<'history>,
        check: OverlayReadCheck,
    ) -> Result<Self, StoreFailure> {
        observation.same_held_scope(observation)?;
        let holder = observation.identity().ok_or_else(invalid)?;
        if !observation.selects_overlay_layer(target)
            || check.inputs.target != target
            || holder.root() != selected.identity().root()
            || holder.physical_identity() != selected.identity().physical_identity()
            || !std::ptr::eq(
                holder.retained_namespace()?,
                selected.identity().retained_namespace()?,
            )
        {
            return Err(invalid());
        }
        check.recheck()?;
        Ok(Self {
            target,
            observation,
            selected,
            check,
        })
    }

    /// Requires the same immutable target and exact original observation purpose.
    ///
    /// # Errors
    /// Refuses changed target, holder, resolver or interpretation distinctions.
    pub(in crate::guard) fn check(
        &self,
        target: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        if target != self.target {
            return Err(invalid());
        }
        self.observation.same_held_scope(observation)?;
        self.check.recheck()
    }

    /// Borrows the actual invocation's grantless overlay input check.
    pub(in crate::guard) fn read_check(&self) -> &OverlayReadCheck {
        &self.check
    }
}

/// Retains the full owning walk until its same overlay recipes physically close.
pub(crate) struct PendingOverlayHistory<'scope, 'history, 'held> {
    /// Holds complete semantic history with no promoted contextual inputs yet.
    pub(in crate::guard) history: Box<VerifiedHistory>,
    /// Preserves the actual immutable target, independently from current refs.
    pub(in crate::guard) requested: Digest,
    /// Borrows the same actual holder and consumed resolver for this walk.
    pub(in crate::guard) observation: HistoryObservation<'history>,
    /// Borrows the exact native overlay purpose whose original recipes must close.
    pub(in crate::guard) purpose: &'scope OverlayPurpose<'history, 'held>,
    /// Borrows one sealed per-invocation canonical DATA ledger.
    pub(in crate::guard) reads: &'scope dyn crate::bucket::held::OverlayNodeReads,
    /// Retains every contextual preparation without completing or caching it.
    pub(in crate::guard) pending_uses: BTreeMap<Digest, super::history::completion::PendingViewUse>,
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Promotes only the same fully walked and physically closed overlay history.
    ///
    /// # Errors
    /// Refuses changed purposes, scopes or conflicting contextual preparations.
    pub(in crate::guard) fn promote_overlay_history<'scope, 'history, 'held>(
        &self,
        pending: PendingOverlayHistory<'scope, 'history, 'held>,
        checked: CheckedOverlayHistoryInputs<'scope, 'history, 'held>,
    ) -> Result<VerifiedHistory, StoreFailure> {
        checked.check_purpose(pending.purpose)?;
        pending
            .purpose
            .check(pending.requested, pending.observation)?;
        checked.check_reader_scope(pending.reads)?;
        self.promote_prepared_view_inputs::<false, false>(
            pending.requested,
            pending.observation,
            pending.pending_uses,
            &pending.history,
        )?;
        Ok(*pending.history)
    }
}
