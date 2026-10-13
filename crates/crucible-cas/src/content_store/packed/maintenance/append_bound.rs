//! Conservative append geometry for the actual bounded mutation algorithm.
//!
//! Each <=64-row window visits at most one old root and one affected subtree per
//! input at every lower level. Each affected node emits at most two pages, and
//! a root split emits one more. The subsequent pack-record point update keeps
//! its separate conservative allowance, including heights raised by the windows.
//! Wider transactions sum window bounds; the on-disk 64-row fan-in is unchanged.

use super::{StoreError, wire};

#[cfg(test)]
mod tests;

/// Bounds one mutation's record changes and native arena append pages.
pub(super) struct AppendBound {
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
    pub(super) fn batch(height: u8, objects: u64) -> Result<Self, StoreError> {
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

    // Each <=64 insertion emits at most two replacements per old child.
    // A raised root starts with exactly two children. Across at most three
    // remaining windows it can grow to at most 2 * 2^3 = 16 children, below
    // the unchanged fan-in64. Thus the complete transaction raises height
    // at most once. The first window uses h; remaining windows use h+1.
    // Each window's unused pack allowance remains conservative; the final
    // allowance covers the sole actual pack-record point update.
    fn publication(height: u8, objects: u64) -> Result<Self, StoreError> {
        let mut remaining = objects;
        let mut raised = height;
        let mut pages = 0_u64;
        while remaining != 0 {
            let count = remaining.min(wire::MAX_ROWS as u64);
            let window = Self::batch(raised, count)?;
            pages = pages.checked_add(window.pages).ok_or(StoreError::Quota)?;
            remaining -= count;
            raised = height.checked_add(1).ok_or(StoreError::Quota)?;
        }
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
    pub(super) fn bytes(&self) -> Result<u64, StoreError> {
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
