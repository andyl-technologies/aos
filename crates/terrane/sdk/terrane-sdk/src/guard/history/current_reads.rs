//! Binds ordinary current history preparation to its actual held read scope.
//!
//! Scope binding preserves the requested-target interpretation. Semantic tree
//! and history checks remain pending until the native producer independently
//! closes physical, selected and Original dependencies for the same invocation.

use super::{Guard, HistoryObservation, VerifiedTree, invalid};
use crate::bucket::held::{CurrentNodeReads, HeldIdentity};
use crate::guard::consumed::ConsumedResolver;
use crate::guard::current_history::{CurrentPurpose, PendingCurrentHistory};
use crate::store::{Clock, Store, StoreFailure};
use terrane_format::identity::Digest;

#[cfg(test)]
mod tests;

impl<'history> HistoryObservation<'history> {
    /// Reports ordinary decoding scope without borrowing any operation evidence.
    ///
    /// Requested-target interpretation is independent of synchronization and
    /// remains valid when the native producer binds an ordinary observation.
    pub(crate) fn is_ordinary_unheld(self) -> bool {
        self.held.is_none()
            && self.consumed.is_none()
            && self.candidate.is_none()
            && self.maintenance.is_none()
            && self.overlay_layer.is_none()
            && self.paired_transition_purpose().is_none()
    }

    /// Requires the same actual held inputs without changing their interpretation.
    ///
    /// # Errors
    /// Refuses missing or substituted holders, resolvers, candidate, maintenance,
    /// requested-target or overlay inputs.
    pub(crate) fn same_held_scope(self, other: Self) -> Result<(), StoreFailure> {
        let same_candidate = match (self.candidate, other.candidate) {
            (None, None) => true,
            (Some(left), Some(right)) => std::ptr::eq(left, right),
            _ => false,
        };
        let same_maintenance = match (self.maintenance, other.maintenance) {
            (None, None) => true,
            (Some(left), Some(right)) => std::ptr::eq(left, right),
            _ => false,
        };

        if !std::ptr::eq(
            self.held.ok_or_else(invalid)?,
            other.held.ok_or_else(invalid)?,
        ) || !std::ptr::eq(
            self.consumed.ok_or_else(invalid)?,
            other.consumed.ok_or_else(invalid)?,
        ) || !self.same_paired_transition(other)
            || !same_candidate
            || !same_maintenance
            || self.requested_target != other.requested_target
            || self.overlay_layer != other.overlay_layer
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Requires exactly the same actual current holder, resolver and interpretation.
    ///
    /// This compares borrowed operation inputs only; it grants no authorization
    /// and cannot promote pending history or qualify physical completion.
    ///
    /// # Errors
    /// Rejects absent or substituted holders and resolvers, candidate,
    /// maintenance or layer scope, and a changed requested-target interpretation.
    pub(crate) fn same_current_scope(self, other: Self) -> Result<(), StoreFailure> {
        let held = self.held.ok_or_else(invalid)?;
        let other_held = other.held.ok_or_else(invalid)?;
        let consumed = self.consumed.ok_or_else(invalid)?;
        let other_consumed = other.consumed.ok_or_else(invalid)?;

        if !std::ptr::eq(held, other_held)
            || !std::ptr::eq(consumed, other_consumed)
            || self.paired_transition_purpose().is_some()
            || other.paired_transition_purpose().is_some()
            || self.candidate.is_some()
            || other.candidate.is_some()
            || self.maintenance.is_some()
            || other.maintenance.is_some()
            || self.overlay_layer.is_some()
            || other.overlay_layer.is_some()
            || self.requested_target != other.requested_target
        {
            return Err(invalid());
        }

        Ok(())
    }

    /// Binds an ordinary observation to the native producer's actual read scope.
    ///
    /// The existing requested-target interpretation survives binding; no
    /// candidate selection or maintenance purpose is introduced.
    ///
    /// # Errors
    /// Rejects observations already borrowing operation evidence or selecting
    /// candidate, maintenance or overlay-layer interpretation.
    pub(crate) fn current_held_from_ordinary(
        mut self,
        held: &'history HeldIdentity<'history>,
        consumed: &'history ConsumedResolver,
    ) -> Result<Self, StoreFailure> {
        if !self.is_ordinary_unheld() {
            return Err(invalid());
        }

        self.held = Some(held);
        self.consumed = Some(consumed);
        Ok(self)
    }

    /// Requires this exact native immutable scope without admitting other purposes.
    ///
    /// # Errors
    /// Refuses foreign holders, resolvers or nonordinary interpretation purposes.
    pub(crate) fn same_direct_scope(self, other: Self) -> Result<(), StoreFailure> {
        self.same_current_scope(other)
    }

    /// Binds only an ordinary direct observation to its genuine native read scope.
    ///
    /// # Errors
    /// Refuses held, candidate, maintenance, overlay or paired observations.
    pub(crate) fn direct_held_from_ordinary(
        self,
        held: &'history HeldIdentity<'history>,
        consumed: &'history ConsumedResolver,
    ) -> Result<Self, StoreFailure> {
        self.current_held_from_ordinary(held, consumed)
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Prepares the signed target and complete history under one current reader.
    ///
    /// The native producer installs its actual `CurrentHistoryStore` adapter
    /// before calling this method. Signed-tree authentication runs first through
    /// that adapter; the unchanged owning history walk then retains unpromoted
    /// preparations. The returned pair supplies no physical completion or ACL
    /// permission.
    ///
    /// # Errors
    /// Rejects a foreign current purpose, holder or token invocation and preserves
    /// every signature, Original, ancestor, disclosure, attribute and index
    /// relationship failure from the owning verifiers.
    pub(crate) async fn prepare_current_tree_with_node_reads<'scope, 'history, 'held>(
        &self,
        view: Digest,
        observation: HistoryObservation<'history>,
        purpose: &'scope CurrentPurpose<'history, 'held>,
        reads: &'scope dyn CurrentNodeReads,
    ) -> Result<(VerifiedTree, PendingCurrentHistory<'scope, 'history, 'held>), StoreFailure> {
        purpose.check(view, observation)?;
        reads.check_holder(observation.identity().ok_or_else(invalid)?)?;
        reads.check_current(purpose.current())?;

        let tree = self.signed_tree(view, observation).await?;
        let pending = self
            .prepare_current_history_with_node_reads(view, observation, purpose, reads)
            .await?;
        Ok((tree, pending))
    }

    /// Prepares the signed target and complete history under one held authorization reader.
    ///
    /// The native producer installs its actual `HeldHistoryStore` adapter
    /// before calling this method. Signed-tree authentication runs first through
    /// that adapter; the unchanged owning history walk then retains unpromoted
    /// preparations. The returned pair supplies no physical completion or ACL
    /// permission.
    ///
    /// # Errors
    /// Rejects a foreign held purpose, holder or token invocation and preserves
    /// every signature, Original, ancestor, disclosure, attribute and index
    /// relationship failure from the owning verifiers.
    pub(crate) async fn prepare_held_tree_with_node_reads<'scope, 'history, 'held>(
        &self,
        view: Digest,
        observation: HistoryObservation<'history>,
        purpose: &'scope crate::guard::held_history::HeldPurpose<'history, 'held>,
        reads: &'scope dyn CurrentNodeReads,
    ) -> Result<
        (
            VerifiedTree,
            crate::guard::held_history::PendingHeldHistory<'scope, 'history, 'held>,
        ),
        StoreFailure,
    > {
        purpose.check(view, observation)?;
        reads.check_holder(observation.identity().ok_or_else(invalid)?)?;
        reads.check_current(purpose.current())?;

        let tree = self.signed_tree(view, observation).await?;
        let pending = self
            .prepare_held_history_with_node_reads(view, observation, purpose, reads)
            .await?;
        Ok((tree, pending))
    }
}
