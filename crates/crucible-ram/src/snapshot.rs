//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Freezes complete logical RAM identity using immutable persistent region trees.

use crate::budget::Reservation;
use crate::{
    MetadataBudget, PageDigest, RamError, RamRootDigest, RegionTree, RootRecord, Scope, Topology,
};
use std::sync::Arc;

#[derive(Debug)]
struct SnapshotInner {
    topology: Topology,
    trees: Vec<RegionTree>,
    budget: MetadataBudget,
    _charge: Reservation,
}

/// An immutable complete RAM identity view, without backing or execution authority.
///
/// Cloning shares trees and their metadata lifetime. A new version replaces only
/// changed paths; retained snapshots never observe later updates. Callers retain
/// the matching immutable bytes or authenticated storage leases separately.
#[derive(Clone, Debug)]
pub struct RamSnapshot {
    inner: Arc<SnapshotInner>,
}

impl RamSnapshot {
    /// Validates one immutable tree per region in canonical inventory order.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for missing/extra regions, geometry mismatches, or
    /// insufficient metadata budget for the snapshot's region-root catalog.
    pub fn new(
        topology: Topology,
        trees: Vec<RegionTree>,
        budget: &MetadataBudget,
    ) -> Result<Self, RamError> {
        if trees.len() != topology.regions().len() {
            return Err(RamError::InvalidLength);
        }
        if trees
            .iter()
            .zip(topology.regions())
            .any(|(tree, region)| tree.geometry() != region.geometry())
        {
            return Err(RamError::InvalidLength);
        }
        let bytes = trees
            .capacity()
            .checked_mul(std::mem::size_of::<RegionTree>())
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<SnapshotInner>() + 2 * std::mem::size_of::<usize>(),
                )
            })
            .ok_or(RamError::Overflow)?;
        let charge = budget.reserve(bytes as u64)?;
        Ok(Self {
            inner: Arc::new(SnapshotInner {
                topology,
                trees,
                budget: budget.clone(),
                _charge: charge,
            }),
        })
    }

    /// Returns the complete logical inventory.
    pub fn topology(&self) -> &Topology {
        &self.inner.topology
    }

    /// Returns all region trees in canonical inventory order.
    pub fn region_trees(&self) -> &[RegionTree] {
        &self.inner.trees
    }

    /// Looks up an immutable tree by its stable owner identifier.
    pub fn region_tree(&self, id: &str) -> Option<&RegionTree> {
        self.inner
            .topology
            .regions()
            .binary_search_by(|region| region.id().as_bytes().cmp(id.as_bytes()))
            .ok()
            .map(|index| &self.inner.trees[index])
    }

    /// Constructs a complete portable root record for the selected scope.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::Allocation`] if the bounded selected-root vector cannot
    /// be allocated, or an invariant validation error.
    pub fn root_record(&self, scope: Scope) -> Result<RootRecord, RamError> {
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(self.inner.trees.len())
            .map_err(|_| RamError::Allocation)?;
        for (region, tree) in self.inner.topology.regions().iter().zip(&self.inner.trees) {
            if scope.includes(region.class()) {
                roots.push(tree.digest());
            }
        }
        RootRecord::new(self.inner.topology.clone(), scope, roots)
    }

    /// Computes the selected scoped root without reading guest RAM.
    ///
    /// # Errors
    ///
    /// Returns errors from constructing the complete [`RootRecord`].
    pub fn scoped_root(&self, scope: Scope) -> Result<RamRootDigest, RamError> {
        Ok(self.root_record(scope)?.digest())
    }

    /// Returns a new snapshot with an atomic batch of one region's page updates.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for unknown regions, invalid page updates, allocation
    /// failure, or metadata exhaustion. The original snapshot stays unchanged.
    pub fn updated(
        &self,
        region_id: &str,
        updates: &[(u64, PageDigest)],
    ) -> Result<Self, RamError> {
        let index = self
            .inner
            .topology
            .regions()
            .binary_search_by(|region| region.id().as_bytes().cmp(region_id.as_bytes()))
            .map_err(|_| RamError::OutOfRange)?;
        let tree = self.inner.trees[index].updated(updates)?;
        if tree.shares_root_with(&self.inner.trees[index]) {
            return Ok(self.clone());
        }
        let work_bytes = self
            .inner
            .trees
            .len()
            .checked_mul(std::mem::size_of::<RegionTree>())
            .ok_or(RamError::Overflow)?;
        let _work = self.inner.budget.reserve(work_bytes as u64)?;
        let mut trees = Vec::new();
        trees
            .try_reserve_exact(self.inner.trees.len())
            .map_err(|_| RamError::Allocation)?;
        trees.extend(self.inner.trees.iter().cloned());
        trees[index] = tree;
        Self::new(self.inner.topology.clone(), trees, &self.inner.budget)
    }
}
