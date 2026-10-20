//! Retains root-bound graft addresses captured by complete namespace validation.
//!
//! These immutable addresses select containing entries only. They convey no
//! policy, signed history, producer, Original, lease or publication authority.

use std::collections::{BTreeMap, BTreeSet};

use terrane_format::identity::Digest;
use terrane_format::tree_format::{Entry, EntryKind, MAX_GRAFT_DEPTH, TreeUse};

use super::invalid;
use crate::store::StoreFailure;

/// Counts address capture within complete independent namespace validation.
///
/// These actual visits and copies establish no incremental maintenance bound
/// and provide no policy, history, producer, Original or publication authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IndexGraftValidationWork {
    /// Distinct canonical owning roots reconstructed by the validator.
    pub owners: usize,
    /// Physical Nodes decoded in those existing reconstruction traversals.
    pub node_visits: usize,
    /// Top-level entries whose graft metadata was captured during validation.
    pub entry_visits: usize,
    /// Entry values inspected, including Conflict candidates and present bases.
    pub nested_entry_visits: usize,
    /// Physical Tree slots captured, preserving repeated placements.
    pub graft_slots: usize,
    /// Containing-entry key bytes copied into retained reverse addresses.
    pub key_bytes: usize,
    /// Actual reverse-address insertion requests, including repeated slots.
    pub addresses: usize,
    /// Root-depth checks, including repeated maximum-depth improvements.
    pub depth_checks: usize,
    /// Captured unique graft edges processed by the depth certificate.
    pub depth_edges: usize,
}

/// Identifies one physical Tree slot, preserving candidate and base duplicates.
pub(crate) struct GraftAddress {
    /// Exact immutable root containing this physical slot.
    pub(crate) owner: Digest,
    /// Full root-local containing-entry key, shared by candidate/base slots.
    pub(crate) key: Vec<u8>,
}

#[derive(Default)]
struct Owner {
    slots: usize,
    children: BTreeSet<Digest>,
    depth: usize,
}

/// Shares addresses only after complete canonical namespace validation succeeds.
pub(crate) struct ValidatedGrafts {
    root: Digest,
    minimum: u64,
    usage: TreeUse,
    certified_depth: bool,
    owners: BTreeMap<Digest, Owner>,
    by_target: BTreeMap<Digest, Vec<GraftAddress>>,
    work: IndexGraftValidationWork,
}

impl ValidatedGrafts {
    /// Checks the exact immutable namespace and physical interpretation.
    pub(crate) fn matches(&self, root: Digest, minimum: u64, usage: TreeUse) -> bool {
        self.root == root && self.minimum == minimum && self.usage == usage
    }

    /// Returns the exact independently validated namespace root.
    pub(crate) fn root(&self) -> Digest {
        self.root
    }

    /// Returns certified maximum occurrence depth and physical slot cardinality.
    ///
    /// Returns `None` for an absent owner or an unavailable depth certificate.
    pub(crate) fn owner(&self, owner: Digest) -> Option<(usize, usize)> {
        if !self.certified_depth {
            return None;
        }
        self.owners
            .get(&owner)
            .map(|owner| (owner.depth, owner.slots))
    }

    /// Borrows every captured physical placement of the exact immutable target.
    pub(crate) fn locations(&self, target: Digest) -> &[GraftAddress] {
        self.by_target.get(&target).map_or(&[], Vec::as_slice)
    }

    /// Returns actual capture and certification costs from independent validation.
    pub(crate) fn work(&self) -> IndexGraftValidationWork {
        self.work
    }
}

/// Captures addresses within the validator's existing physical leaf traversal.
#[derive(Default)]
pub(super) struct Capture {
    owners: BTreeMap<Digest, Owner>,
    by_target: BTreeMap<Digest, Vec<GraftAddress>>,
    work: IndexGraftValidationWork,
}

impl Capture {
    /// Starts capture for one owner in the validator's canonical reconstruction.
    ///
    /// # Errors
    /// Rejects repeated owners and operation-count overflow.
    pub(super) fn begin(&mut self, owner: Digest) -> Result<(), StoreFailure> {
        if self.owners.insert(owner, Owner::default()).is_some() {
            return Err(invalid());
        }
        add(&mut self.work.owners, 1)
    }

    /// Charges one physical Node decoded by the existing reconstruction loop.
    ///
    /// # Errors
    /// Rejects operation-count overflow.
    pub(super) fn node(&mut self) -> Result<(), StoreFailure> {
        add(&mut self.work.node_visits, 1)
    }

    /// Captures every Tree slot while the validator transfers one decoded entry.
    ///
    /// Candidate and present-base placements remain distinct even when owner,
    /// key and target are identical. The containing key is copied per slot.
    ///
    /// # Errors
    /// Rejects an unregistered owner and operation or byte-count overflow.
    pub(super) fn item(
        &mut self,
        owner: Digest,
        key: &[u8],
        entry: &Entry<'_>,
    ) -> Result<(), StoreFailure> {
        add(&mut self.work.entry_visits, 1)?;
        let mut pending = vec![entry];
        while let Some(entry) = pending.pop() {
            add(&mut self.work.nested_entry_visits, 1)?;
            match &entry.kind {
                EntryKind::Tree { root, .. } => {
                    let metadata = self.owners.get_mut(&owner).ok_or_else(invalid)?;
                    add(&mut metadata.slots, 1)?;
                    metadata.children.insert(*root);
                    self.by_target.entry(*root).or_default().push(GraftAddress {
                        owner,
                        key: key.to_vec(),
                    });
                    add(&mut self.work.graft_slots, 1)?;
                    add(&mut self.work.addresses, 1)?;
                    add(&mut self.work.key_bytes, key.len())?;
                }
                EntryKind::Conflict { candidates, base } => {
                    pending.extend(candidates);
                    if let Some(Some(base)) = base {
                        pending.push(base);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Certifies maximum occurrence depth without rereading namespace entries.
    ///
    /// Unique captured edges may be revisited when a longer path is discovered;
    /// every visit is charged and depth is bounded by the physical protocol.
    ///
    /// # Errors
    /// Rejects missing captured owners and operation-count overflow. Cycles or
    /// excessive depth produce an unusable certificate, preserving the existing
    /// occurrence validator's refusal rather than changing physical loading.
    pub(super) fn finish(
        mut self,
        root: Digest,
        minimum: u64,
        usage: TreeUse,
    ) -> Result<ValidatedGrafts, StoreFailure> {
        let mut pending = vec![(root, 1_usize)];
        let mut certified_depth = true;
        while let Some((owner, depth)) = pending.pop() {
            add(&mut self.work.depth_checks, 1)?;
            if depth > MAX_GRAFT_DEPTH + 1 {
                // Physical loading historically leaves cycles/depth refusal to
                // occurrence validation. An unavailable certificate preserves
                // that behavior and can never qualify a maintenance plan.
                certified_depth = false;
                break;
            }
            let metadata = self.owners.get_mut(&owner).ok_or_else(invalid)?;
            if metadata.depth >= depth {
                continue;
            }
            metadata.depth = depth;
            for child in &metadata.children {
                add(&mut self.work.depth_edges, 1)?;
                pending.push((*child, depth + 1));
            }
        }
        // Every retained owner must originate in this exact reached namespace.
        for owner in self.owners.values() {
            add(&mut self.work.depth_checks, 1)?;
            if owner.depth == 0 {
                certified_depth = false;
            }
        }
        Ok(ValidatedGrafts {
            root,
            minimum,
            usage,
            certified_depth,
            owners: self.owners,
            by_target: self.by_target,
            work: self.work,
        })
    }
}

#[cfg(test)]
mod tests;

fn add(counter: &mut usize, amount: usize) -> Result<(), StoreFailure> {
    *counter = counter.checked_add(amount).ok_or_else(invalid)?;
    Ok(())
}
