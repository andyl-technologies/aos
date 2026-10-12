//! Retains the selected reachable immutable namespace handles in one snapshot.
//!
//! Preparation builds this digest-sorted table once. Clones share its allocation;
//! lookups inspect only this table, never the caller's arbitrary source map or a
//! chain of earlier generations. Lookup work is ordinary bookkeeping, not B.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cmp::Ordering;

use super::Error;
use crate::identity::Digest;
use crate::tree_builder::Tree;

/// Counts actual relevant-root lookup operations separately from physical work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SourceLookupWork {
    /// Lookup calls, including unsuccessful calls.
    pub calls: usize,
    /// Sorted-table slots inspected by binary search.
    pub probes: usize,
    /// Digest comparison calls, one per inspected slot.
    pub comparisons: usize,
}

/// Shares borrowed immutable Trees from one independently prepared closure.
///
/// Each distinct reachable digest has exactly one handle. Repeated grafts still
/// retain separate occurrence contexts in discovery; storage sharing does not
/// deduplicate traversal. This type conveys no current authority or coverage.
#[derive(Clone, Debug)]
pub struct SourceLookup<'graph, 'value> {
    trees: Rc<Vec<(Digest, &'graph Tree<'value>)>>,
}

impl<'graph, 'value> SourceLookup<'graph, 'value> {
    /// Retains the preparation-owned, digest-sorted distinct-root table.
    pub(super) fn new(trees: Vec<(Digest, &'graph Tree<'value>)>) -> Self {
        Self {
            trees: Rc::new(trees),
        }
    }

    /// Returns the exact number of distinct reachable immutable roots retained.
    pub fn root_count(&self) -> usize {
        self.trees.len()
    }

    /// Borrows a selected immutable Tree while charging actual lookup operations.
    ///
    /// The result borrows the original immutable graph, independently of this
    /// snapshot's lifetime. Cloning or dropping a snapshot cannot alter the Tree.
    /// No entries, source-map slots, or prior snapshots are enumerated.
    ///
    /// # Errors
    /// Returns `MissingSource` for a digest outside the selected closure and
    /// `Limit` when a work counter overflows.
    pub fn tree(
        &self,
        root: Digest,
        work: &mut SourceLookupWork,
    ) -> Result<&'graph Tree<'value>, Error> {
        add(&mut work.calls)?;
        let mut start = 0;
        let mut end = self.trees.len();

        while start < end {
            let middle = start + (end - start) / 2;
            add(&mut work.probes)?;
            add(&mut work.comparisons)?;
            let (digest, tree) = self.trees[middle];
            match digest.cmp(&root) {
                Ordering::Less => start = middle + 1,
                Ordering::Greater => end = middle,
                Ordering::Equal => return Ok(tree),
            }
        }

        Err(Error::MissingSource)
    }
}

impl PartialEq for SourceLookup<'_, '_> {
    fn eq(&self, other: &Self) -> bool {
        // Preparation checks canonical identity, so equal selected root lists
        // identify the same immutable data without comparing Tree internals.
        self.trees.len() == other.trees.len()
            && self
                .trees
                .iter()
                .zip(other.trees.iter())
                .all(|(left, right)| left.0 == right.0)
    }
}

impl Eq for SourceLookup<'_, '_> {}

fn add(counter: &mut usize) -> Result<(), Error> {
    *counter = counter.checked_add(1).ok_or(Error::Limit)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "fixtures assert canonical immutable construction"
    )]
    use super::*;
    use crate::chunking::CDC_1M_MIN;
    use crate::tree_format::TreeUse;

    #[test]
    fn clones_share_one_flat_snapshot_without_generation_chains() {
        let tree = Tree::build(Vec::new(), None, CDC_1M_MIN as u64, TreeUse::Ordinary).unwrap();
        let root = tree.root_identity();
        let snapshot = SourceLookup::new(alloc::vec![(root, &tree)]);
        let mut latest = snapshot.clone();
        for _ in 0..4096 {
            latest = latest.clone();
            assert!(Rc::ptr_eq(&snapshot.trees, &latest.trees));
            assert_eq!(Rc::strong_count(&snapshot.trees), 2);
        }
        let mut work = SourceLookupWork::default();
        assert!(core::ptr::eq(latest.tree(root, &mut work).unwrap(), &tree));
        assert_eq!(
            work,
            SourceLookupWork {
                calls: 1,
                probes: 1,
                comparisons: 1
            }
        );
    }

    #[test]
    fn lookup_counter_overflow_refuses_without_wrapping() {
        let snapshot = SourceLookup::new(Vec::new());
        let mut work = SourceLookupWork {
            calls: usize::MAX,
            ..SourceLookupWork::default()
        };
        assert!(matches!(
            snapshot.tree([0; 32], &mut work),
            Err(Error::Limit)
        ));
        assert_eq!(work.calls, usize::MAX);
        assert_eq!(work.probes, 0);
        assert_eq!(work.comparisons, 0);

        let tree = Tree::build(Vec::new(), None, CDC_1M_MIN as u64, TreeUse::Ordinary).unwrap();
        let root = tree.root_identity();
        let snapshot = SourceLookup::new(alloc::vec![(root, &tree)]);
        let mut probes = SourceLookupWork {
            probes: usize::MAX,
            ..SourceLookupWork::default()
        };
        assert!(matches!(
            snapshot.tree(root, &mut probes),
            Err(Error::Limit)
        ));
        assert_eq!(
            probes,
            SourceLookupWork {
                calls: 1,
                probes: usize::MAX,
                comparisons: 0
            }
        );

        let mut comparisons = SourceLookupWork {
            comparisons: usize::MAX,
            ..SourceLookupWork::default()
        };
        assert!(matches!(
            snapshot.tree(root, &mut comparisons),
            Err(Error::Limit)
        ));
        assert_eq!(
            comparisons,
            SourceLookupWork {
                calls: 1,
                probes: 1,
                comparisons: usize::MAX
            }
        );
    }
}
