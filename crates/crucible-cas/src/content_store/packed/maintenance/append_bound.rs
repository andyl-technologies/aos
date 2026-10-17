//! Conservative append geometry for the actual bounded mutation algorithm.
//!
//! Inputs partition among affected subtrees. A whole group emits balanced
//! <=64-row pages, at most five for any old node. Its checked per-depth bound
//! counts actual output possibilities, followed by the independent pack-record
//! point update. Physical failed tails remain charged by the enclosing owner.

use super::{StoreError, wire};

#[cfg(test)]
mod tests;

/// Bounds one mutation's record changes and native arena append pages.
pub(in crate::content_store::packed) struct AppendBound {
    pub(super) changes: u64,
    pages: u64,
}

impl AppendBound {
    /// Keeps the inherited split, sibling and root allowance for point work.
    ///
    /// # Errors
    ///
    /// Refuses checked page-count overflow.
    pub(super) fn point(height: u8, changes: u64) -> Result<Self, StoreError> {
        Ok(Self {
            changes,
            pages: point_pages(u64::from(height), changes)?,
        })
    }

    /// Bounds one multipoint group and its subsequent pack-record update.
    ///
    /// # Errors
    ///
    /// Refuses checked record-count or page-count overflow.
    pub(in crate::content_store::packed) fn batch(
        height: u8,
        objects: u64,
    ) -> Result<Self, StoreError> {
        let changes = objects.checked_add(1).ok_or(StoreError::Quota)?;
        if objects > wire::MAX_ROWS as u64
            && objects <= crate::content_store::batch::MAX_PUBLICATION_OBJECTS as u64
        {
            return Self::publication(height, objects);
        }
        if !(1..=wire::MAX_ROWS as u64).contains(&objects) {
            // Preserve the old geometry for an invalid private caller. The
            // existing insertion validator retains its later refusal cut.
            return Self::point(height, changes);
        }

        // Inputs partition between children: a visited nonroot subtree has at
        // least one distinct input. No node or validated bytes are cached here.
        let affected = objects
            .checked_mul(u64::from(height))
            .and_then(|nodes| nodes.checked_add(1))
            .ok_or(StoreError::Quota)?;
        let batch_pages = affected
            .checked_mul(2)
            .and_then(|pages| pages.checked_add(1))
            .ok_or(StoreError::Quota)?;
        let raised_height = u64::from(height).checked_add(1).ok_or(StoreError::Quota)?;
        let pack_pages = point_pages(raised_height, 1)?;
        let combined_pages = batch_pages
            .checked_add(pack_pages)
            .ok_or(StoreError::Quota)?;
        // The inherited point allowance is tighter for a singleton inline
        // group. Keep that conservative bound rather than require more space.
        let pages = combined_pages.min(point_pages(u64::from(height), changes)?);
        Ok(Self { changes, pages })
    }

    // For k affected nodes at a depth, input counts r_i sum to n. Each
    // old node has <=64 rows, so q_i <= 1 + ceil(r_i/64). Thus total outputs
    // <= k + floor((n + 63*k)/64) <= 2*k + floor(n/64), with k <= n.
    // The old root emits <=1+ceil(n/64); a split adds one new root. The
    // subsequent point update is bounded at the resulting height h+1.
    fn publication(height: u8, objects: u64) -> Result<Self, StoreError> {
        let width = wire::MAX_ROWS as u64;
        let root_pages = objects
            .checked_add(width - 1)
            .and_then(|count| count.checked_div(width))
            .and_then(|pages| pages.checked_add(1))
            .ok_or(StoreError::Quota)?;
        let per_depth = objects
            .checked_mul(2)
            .and_then(|pages| pages.checked_add(objects / width))
            .ok_or(StoreError::Quota)?;
        let object_pages = per_depth
            .checked_mul(u64::from(height))
            .and_then(|pages| pages.checked_add(root_pages))
            .and_then(|pages| pages.checked_add(1))
            .ok_or(StoreError::Quota)?;
        let pack_height = u64::from(height).checked_add(1).ok_or(StoreError::Quota)?;
        let pages = object_pages
            .checked_add(point_pages(pack_height, 1)?)
            .ok_or(StoreError::Quota)?;
        Ok(Self {
            changes: objects.checked_add(1).ok_or(StoreError::Quota)?,
            pages,
        })
    }

    /// Converts the append page allowance into native arena bytes.
    ///
    /// # Errors
    ///
    /// Refuses checked byte-count overflow.
    pub(in crate::content_store::packed) fn bytes(&self) -> Result<u64, StoreError> {
        self.pages
            .checked_mul(wire::PAGE_BYTES as u64)
            .ok_or(StoreError::Quota)
    }
}

fn point_pages(height: u64, changes: u64) -> Result<u64, StoreError> {
    // Retains the existing split/sibling-pair and root-endpoint bound.
    height
        .checked_add(1)
        .and_then(|levels| levels.checked_mul(4))
        .and_then(|pages| pages.checked_add(2))
        .and_then(|pages| pages.checked_mul(changes))
        .ok_or(StoreError::Quota)
}
