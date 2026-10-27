//! Completes an independent owning history walk under an existing held scope.
//!
//! The purpose retains every interpretation in the actual observation. Sharing
//! immutable DATA never substitutes completed history or grants current ACLs.

use super::current_history::PendingCurrentReadCheck;
use super::{Guard, HistoryObservation, invalid};
use crate::bucket::{
    BucketBinding,
    publication::{SelectedObservation, receipts::RecordRead},
};
use crate::store::{Clock, LocalFs, Store, StoreFailure};
use std::collections::BTreeMap;
use terrane_format::gc::publication::evidence::{PhysicalRegistration, RequiredControlPin};
use terrane_format::identity::Digest;
use terrane_format::provenance::VerifiedHistory;
use terrane_format::refs::RefRecord;

mod store;

pub(in crate::guard) use store::HeldHistoryStore;

#[cfg(test)]
mod tests;

/// Binds one held-purpose owning-history walk to its actual whole ref and held observation.
///
/// Borrowing this purpose retains no permission. Candidate, maintenance and
/// requested-target distinctions stay bound to their actual observation. Every
/// authorization receives a fresh purpose even for the same immutable commit.
pub(crate) struct HeldPurpose<'history, 'held> {
    record: RefRecord,
    observation: HistoryObservation<'history>,
    selected: &'history SelectedObservation<'held>,
    current: PendingCurrentReadCheck,
}

impl<'history, 'held> HeldPurpose<'history, 'held> {
    /// Binds the existing actual held observation and independently read whole ref.
    ///
    /// # Errors
    /// Refuses missing or foreign held/resolver inputs and failed fresh token
    /// authentication without changing the observation purpose.
    pub(in crate::guard) async fn capture<F, B, V>(
        held: &crate::bucket::held::HeldBucket<'_, F, B, V, false>,
        selected: &'history SelectedObservation<'held>,
        reference: &str,
        record: &RefRecord,
        observation: HistoryObservation<'history>,
        current: PendingCurrentReadCheck,
    ) -> Result<Self, StoreFailure>
    where
        F: LocalFs + BucketBinding,
        B: Clock + BucketBinding,
        V: crate::store::ContentValidator + BucketBinding,
    {
        observation.same_held_scope(observation)?;
        current.recheck()?;
        current.check_reference(reference)?;
        if held
            .current_ref_from_observation(selected, reference)
            .await?
            .as_ref()
            != Some(record)
        {
            return Err(invalid());
        }
        let identity = observation.identity().ok_or_else(invalid)?;
        if identity.root() != selected.identity().root()
            || identity.physical_identity() != selected.identity().physical_identity()
            || !std::ptr::eq(
                identity.retained_namespace()?,
                selected.identity().retained_namespace()?,
            )
        {
            return Err(invalid());
        }
        current.recheck()?;
        Ok(Self {
            record: record.clone(),
            observation,
            selected,
            current,
        })
    }

    /// Requires the exact current observation and requested immutable identity.
    ///
    /// # Errors
    /// Refuses changed authentication, a foreign observation or another commit.
    pub(in crate::guard) fn check(
        &self,
        view: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        self.current.recheck()?;
        self.observation.same_held_scope(observation)?;
        if let Some(transition) = observation.paired_transition_purpose() {
            transition.check_scope(observation)?;
        }
        if view != self.record.commit {
            return Err(invalid());
        }
        Ok(())
    }

    /// Borrows the genuine token-only check for this current invocation.
    pub(in crate::guard) fn current(&self) -> &PendingCurrentReadCheck {
        &self.current
    }
}

/// Retains the complete semantic walk until the same current inputs close.
///
/// Only the owning disclosure walker supplies these fields. The value grants
/// no current ACL permission and cannot be consumed as candidate history.
pub(crate) struct PendingHeldHistory<'scope, 'history, 'held> {
    /// The unchanged complete ancestor-first semantic walk awaiting promotion.
    pub(in crate::guard) history: Box<VerifiedHistory>,
    /// The original requested commit identity, never a candidate identity.
    pub(in crate::guard) requested: Digest,
    /// The actual held resolver observation used throughout the walk.
    pub(in crate::guard) observation: HistoryObservation<'history>,
    /// The same current invocation that will supply physical closing evidence.
    pub(in crate::guard) purpose: &'scope HeldPurpose<'history, 'held>,
    /// The actual sealed data reader whose original recipes must close.
    pub(in crate::guard) reads: &'scope dyn crate::bucket::held::CurrentNodeReads,
    /// Every original contextual view preparation, still unpromoted.
    pub(in crate::guard) pending_uses: BTreeMap<Digest, super::history::completion::PendingViewUse>,
}

/// Pairs successful native physical closure with one exact current invocation.
///
/// Only the factory below initializes this carrier after a genuine physical
/// read projection. It supplies no candidate, mutation or ACL permission.
pub(crate) struct CheckedHeldHistoryInputs<'scope, 'history, 'held> {
    purpose: &'scope HeldPurpose<'history, 'held>,
    scope: &'scope dyn crate::bucket::held::CurrentNodeReads,
    pins: Vec<RequiredControlPin>,
    physical: crate::store::native_publication_effects::CurrentHistoryPhysicalInputs<'scope, 'held>,
}

impl<'scope, 'history, 'held> CheckedHeldHistoryInputs<'scope, 'history, 'held> {
    /// Closes original DATA, selected and protected recipes before making proof.
    ///
    /// # Errors
    /// Refuses foreign scopes, missing controls, changed exact pins or original
    /// physical recipes, incomplete reads, authentication failure and unsupported
    /// native retention. A failed close never produces a completion carrier.
    pub(in crate::guard) async fn close<F: LocalFs + BucketBinding>(
        fs: &F,
        observed: &'scope SelectedObservation<'held>,
        purpose: &'scope HeldPurpose<'history, 'held>,
        scope: &'scope dyn crate::bucket::held::CurrentNodeReads,
        controls: &[super::RetainedControls],
        original_reads: &[RecordRead],
    ) -> Result<Self, StoreFailure> {
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut diagnostic =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::HeldClosing);
        purpose.check(purpose.record.commit, purpose.observation)?;
        scope.check_holder(purpose.observation.identity().ok_or_else(invalid)?)?;
        scope.check_selection(observed)?;
        scope.check_current(purpose.current())?;
        if !std::ptr::eq(purpose.selected, observed) {
            return Err(invalid());
        }
        let pins = purpose
            .observation
            .resolver()
            .ok_or_else(invalid)?
            .control_pins()?;
        for pin in &pins {
            let PhysicalRegistration::Local(owner) = &pin.owner else {
                return Err(crate::store::StoreFailure::new(
                    crate::store::StoreErrorKind::Unsupported,
                ));
            };
            let record = controls
                .iter()
                .filter(|retained| {
                    retained.directory().as_os_str().as_encoded_bytes() == owner.control.as_slice()
                })
                .find_map(|retained| {
                    retained
                        .records()
                        .iter()
                        .find(|record| record.path() == retained.directory().join(&pin.key))
                })
                .ok_or_else(invalid)?;
            pin.check_record(record.bytes()).map_err(|_| invalid())?;
        }

        if let Some(transition) = purpose.observation.paired_transition_purpose() {
            transition.check_scope(purpose.observation)?;
            transition.check_selected(fs, observed).await?;
        }
        let payload_reads = scope.begin_closing()?;
        let physical =
            crate::store::native_publication_effects::CurrentHistoryPhysicalInputs::close_held(
                fs,
                observed,
                controls,
                original_reads,
                payload_reads,
                purpose.current(),
                purpose.observation.paired_transition_purpose(),
            )
            .await?;
        let checked = Self {
            purpose,
            scope,
            pins,
            physical,
        };
        checked.check_reader_scope(scope)?;
        scope.complete_held_closing(&checked)?;
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        diagnostic.complete();
        Ok(checked)
    }

    /// Requires this proof's exact reader, invocation and unchanged consumed pins.
    ///
    /// # Errors
    /// Refuses a foreign reader, holder or selected observation, changed resolver
    /// pins and a failed genuine token or time recheck.
    pub(crate) fn check_reader_scope(
        &self,
        scope: &dyn crate::bucket::held::CurrentNodeReads,
    ) -> Result<(), StoreFailure> {
        self.purpose
            .check(self.purpose.record.commit, self.purpose.observation)?;
        if !std::ptr::addr_eq(self.scope, scope) {
            return Err(invalid());
        }
        if !std::ptr::eq(self.purpose.selected, self.physical.observed()) {
            return Err(invalid());
        }
        scope.check_holder(self.purpose.observation.identity().ok_or_else(invalid)?)?;
        scope.check_selection(self.physical.observed())?;
        scope.check_current(self.purpose.current())?;
        if self
            .purpose
            .observation
            .resolver()
            .ok_or_else(invalid)?
            .control_pins()?
            != self.pins
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Promotes the original semantic walk after its exact current inputs close.
    ///
    /// No awaited operation separates physical closing from this owning check.
    /// The caller still performs ordinary current ACL and request authorization.
    ///
    /// # Errors
    /// Refuses foreign purposes, changed current inputs or conflicting contextual
    /// preparations without promoting any pending view.
    pub(in crate::guard) fn promote_held_history<'scope, 'history, 'held>(
        &self,
        pending: PendingHeldHistory<'scope, 'history, 'held>,
        checked: CheckedHeldHistoryInputs<'scope, 'history, 'held>,
    ) -> Result<VerifiedHistory, StoreFailure> {
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        let mut diagnostic =
            crate::diagnostic_clock::span(crate::diagnostic_clock::Group::HeldPromotion);
        if !std::ptr::eq(pending.purpose, checked.purpose) {
            return Err(invalid());
        }
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
        #[cfg(all(test, feature = "std", feature = "tokio"))]
        diagnostic.complete();
        Ok(*pending.history)
    }
}
