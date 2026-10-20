//! Prepares immutable graft addresses and selects only affected containing entries.
//!
//! The factory shares exact reverse addresses retained by independent canonical
//! namespace validation. It never walks namespace entries again. Only changed
//! targets select addresses; neither the cache nor its depth certificate grants
//! history, current policy, producer, Original or publication authority.

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use terrane_format::identity::Digest;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{Entry, EntryKind};

use super::report::{IndexGraftPreparationWork, IndexGraftPropagationWork};
use super::{IndexGraftValidationWork, OwnerPlan};
use crate::guard::invalid;
use crate::guard::snapshot::ValidatedGrafts;
use crate::store::StoreFailure;

/// Names one batch of ordinary containing-entry replacements.
type Edits<'value> = Vec<(Vec<u8>, Option<Entry<'value>>)>;

/// Retains exact immutable entry addresses and operation-local pending edits.
///
/// Every address originates in the verified namespace used by the actual owner
/// plans. The lookup stores owned keys only, so it introduces no Tree, arena or
/// authority borrow across an asynchronous operation.
pub(super) struct PreparedTargets {
    grafts: Option<Arc<ValidatedGrafts>>,
    occurrences: BTreeMap<Digest, usize>,
    ranks: BTreeMap<Digest, usize>,
    pending: BTreeMap<Digest, BTreeSet<Vec<u8>>>,
    visited: BTreeSet<Digest>,
    preparation: IndexGraftPreparationWork,
    propagation: IndexGraftPropagationWork,
}

impl PreparedTargets {
    /// Prepares addresses from the actual reconstructed graph and qualified plans.
    ///
    /// # Errors
    /// Rejects missing or mismatched immutable roots, duplicate plans, inconsistent
    /// child-before-parent ordering and counter overflow. It checks no authority.
    pub(super) fn new(
        graph: &BTreeMap<Digest, Tree<'_>>,
        plans: &[OwnerPlan],
    ) -> Result<Self, StoreFailure> {
        let mut value = Self {
            grafts: plans.first().map(|plan| Arc::clone(&plan.grafts)),
            occurrences: BTreeMap::new(),
            ranks: BTreeMap::new(),
            pending: BTreeMap::new(),
            visited: BTreeSet::new(),
            preparation: IndexGraftPreparationWork::default(),
            propagation: IndexGraftPropagationWork::default(),
        };
        for (rank, plan) in plans.iter().enumerate() {
            if value.ranks.insert(plan.owner, rank).is_some() {
                return Err(invalid());
            }
        }

        let mut previous_depth = usize::MAX;
        for plan in plans {
            let tree = graph.get(&plan.owner).ok_or_else(invalid)?;
            let grafts = value.grafts.as_ref().ok_or_else(invalid)?;
            let namespace = graph.get(&grafts.root()).ok_or_else(invalid)?;
            if !Arc::ptr_eq(grafts, &plan.grafts)
                || !grafts.matches(grafts.root(), namespace.min_chunk_size(), namespace.usage())
                || tree.root_identity() != plan.owner
                || plan.occurrences == 0
            {
                return Err(invalid());
            }
            let (depth, slots) = grafts.owner(plan.owner).ok_or_else(invalid)?;
            if depth != plan.depth || depth > previous_depth {
                return Err(invalid());
            }
            previous_depth = depth;
            value.occurrences.insert(plan.owner, plan.occurrences);
            increment(&mut value.preparation.owners, 1)?;
            increment(&mut value.preparation.owner_occurrences, plan.occurrences)?;
            // These are retained cardinalities, not entry visits. The actual
            // capture/index construction is reported as independent validation.
            increment(&mut value.preparation.graft_slots, slots)?;
            increment(
                &mut value.preparation.graft_occurrences,
                slots.checked_mul(plan.occurrences).ok_or_else(invalid)?,
            )?;
        }

        Ok(value)
    }

    /// Returns handle preparation and retained slot cardinalities, without an entry walk.
    pub(super) fn preparation(&self) -> IndexGraftPreparationWork {
        self.preparation
    }

    /// Returns actual capture work from the existing independent canonical validator.
    pub(super) fn validation(&self) -> IndexGraftValidationWork {
        self.grafts
            .as_ref()
            .map_or_else(IndexGraftValidationWork::default, |grafts| grafts.work())
    }

    /// Returns the actual affected-entry selection and replacement observations.
    pub(super) fn work(&self) -> IndexGraftPropagationWork {
        self.propagation
    }

    /// Reads and edits only keys selected by already completed changed targets.
    ///
    /// # Errors
    /// Rejects an unknown/repeated owner, mismatched immutable input, missing
    /// selected key or counter overflow. Existing replacement semantics apply to
    /// every Tree, Conflict candidate and present Conflict base in that entry.
    pub(super) fn take_edits<'value>(
        &mut self,
        owner: Digest,
        tree: &Tree<'value>,
        replacements: &BTreeMap<Digest, Digest>,
    ) -> Result<Edits<'value>, StoreFailure> {
        if !self.ranks.contains_key(&owner)
            || !self.visited.insert(owner)
            || tree.root_identity() != owner
        {
            return Err(invalid());
        }
        let mut edits = Vec::new();
        for key in self.pending.remove(&owner).unwrap_or_default() {
            increment(&mut self.propagation.entry_lookups, 1)?;
            let mut entry = tree.get(&key).ok_or_else(invalid)?.clone();
            if replace_targets(&mut entry, replacements, &mut self.propagation)? {
                increment(&mut self.propagation.edited_entries, 1)?;
                edits.push((key, Some(entry)));
            }
        }

        Ok(edits)
    }

    /// Selects containing addresses only when the completed target actually changes.
    ///
    /// # Errors
    /// Rejects an unknown or unfinished owner, a containing owner already consumed,
    /// or counter overflow. Equal immutable targets schedule no lookup or edit.
    pub(super) fn complete(
        &mut self,
        owner: Digest,
        replacement: Digest,
    ) -> Result<(), StoreFailure> {
        if !self.ranks.contains_key(&owner) || !self.visited.contains(&owner) {
            return Err(invalid());
        }
        if owner == replacement {
            return Ok(());
        }
        increment(&mut self.propagation.changed_targets, 1)?;
        increment(&mut self.propagation.target_lookups, 1)?;

        let grafts = self.grafts.as_ref().ok_or_else(invalid)?;
        for location in grafts.locations(owner) {
            if self.visited.contains(&location.owner)
                || self.ranks.get(&owner) >= self.ranks.get(&location.owner)
            {
                return Err(invalid());
            }
            increment(&mut self.propagation.address_links, 1)?;
            increment(
                &mut self.propagation.affected_occurrences,
                *self.occurrences.get(&location.owner).ok_or_else(invalid)?,
            )?;
            if self
                .pending
                .entry(location.owner)
                .or_default()
                .insert(location.key.clone())
            {
                increment(&mut self.propagation.selected_entries, 1)?;
            }
        }

        Ok(())
    }
}

fn replace_targets(
    entry: &mut Entry<'_>,
    replacements: &BTreeMap<Digest, Digest>,
    work: &mut IndexGraftPropagationWork,
) -> Result<bool, StoreFailure> {
    increment(&mut work.nested_entry_visits, 1)?;
    match &mut entry.kind {
        EntryKind::Tree { root, .. } => {
            increment(&mut work.replacement_lookups, 1)?;
            if let Some(replacement) = replacements.get(root)
                && replacement != root
            {
                *root = *replacement;
                increment(&mut work.replaced_graft_slots, 1)?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        EntryKind::Conflict { candidates, base } => {
            let mut changed = false;
            for candidate in candidates {
                changed |= replace_targets(candidate, replacements, work)?;
            }
            if let Some(Some(base)) = base {
                changed |= replace_targets(base, replacements, work)?;
            }
            Ok(changed)
        }
        _ => Ok(false),
    }
}

fn increment(counter: &mut usize, amount: usize) -> Result<(), StoreFailure> {
    *counter = counter.checked_add(amount).ok_or_else(invalid)?;
    Ok(())
}
