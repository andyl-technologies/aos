//! Default-off weak hash-cons candidate purging for the execution-176 falsifier.
//!
//! This module removes only weak interning handles. It does not retire, reuse,
//! unmap, or otherwise mutate any heap object named by those handles. A later
//! allocation can therefore rebuild an equivalent value at a distinct stable
//! address while the original object remains valid.

use super::*;

/// Before-and-after storage counts for one weak hash-cons table.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct WeakHashConsTablePurgeReport {
    /// `(buckets, bucket capacity, candidates, candidate capacity)` before purge.
    pub(crate) before: (usize, usize, usize, usize),
    /// `(buckets, bucket capacity, candidates, candidate capacity)` after purge.
    pub(crate) after: (usize, usize, usize, usize),
    /// Retention-pass removal and released-capacity accounting.
    pub(crate) retained: crate::hashcons::HashConsRetainReport,
}

/// Per-table result of one exact candidate-address purge.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct WeakHashConsPurgeReport {
    /// String interning table result.
    pub(crate) string: WeakHashConsTablePurgeReport,
    /// Path interning table result.
    pub(crate) path: WeakHashConsTablePurgeReport,
    /// List interning table result.
    pub(crate) list: WeakHashConsTablePurgeReport,
    /// Attribute-set interning table result.
    pub(crate) attrs: WeakHashConsTablePurgeReport,
}

impl EvalHeap {
    /// Removes exact candidate addresses from all evaluator weak interning tables.
    ///
    /// The caller must establish that `candidate_addresses` is the complete
    /// admitted checkpoint cohort. This operation deliberately leaves the
    /// objects themselves allocated and fully resolvable.
    pub(crate) fn purge_weak_hash_cons_candidates(
        &mut self,
        sorted_candidate_addresses: &[usize],
    ) -> WeakHashConsPurgeReport {
        WeakHashConsPurgeReport {
            string: purge_table(&mut self.string_cons, sorted_candidate_addresses),
            path: purge_table(&mut self.path_cons, sorted_candidate_addresses),
            list: purge_table(&mut self.list_cons, sorted_candidate_addresses),
            attrs: purge_table(&mut self.attrs_cons, sorted_candidate_addresses),
        }
    }
}

/// Purges one table by native heap address and records exact storage counts.
fn purge_table(
    table: &mut HashConsTable<HotXxh3Hash, Value>,
    sorted_candidate_addresses: &[usize],
) -> WeakHashConsTablePurgeReport {
    let before = table.storage_counts();
    let retained = table.retain_committed(|value| match value.as_heap_ptr() {
        Ok(pointer) => sorted_candidate_addresses
            .binary_search(&(pointer.as_ptr() as usize))
            .is_err(),
        Err(_) => true,
    });
    let after = table.storage_counts();
    debug_assert_eq!(
        before.2.saturating_sub(after.2),
        retained.candidates_removed
    );
    WeakHashConsTablePurgeReport {
        before,
        after,
        retained,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_drops_only_exact_weak_candidates_without_retiring_objects() {
        let mut heap = EvalHeap::new();
        let removed = heap
            .alloc_string(NixString::from_bytes(b"removed".to_vec()))
            .expect("removed string allocates");
        let retained = heap
            .alloc_string(NixString::from_bytes(b"retained".to_vec()))
            .expect("retained string allocates");
        let removed_address = removed
            .as_string_ptr()
            .expect("removed string has a pointer")
            .as_ptr() as usize;

        let report = heap.purge_weak_hash_cons_candidates(&[removed_address]);

        assert_eq!(report.string.before.2, 2);
        assert_eq!(report.string.after.2, 1);
        assert_eq!(report.string.retained.candidates_removed, 1);
        assert_eq!(
            heap.get_string(removed)
                .expect("purged object remains resolvable")
                .bytes(),
            b"removed"
        );
        let retained_again = heap
            .alloc_string(NixString::from_bytes(b"retained".to_vec()))
            .expect("retained intern entry remains reusable");
        assert!(retained_again.raw_eq(retained));
        let removed_again = heap
            .alloc_string(NixString::from_bytes(b"removed".to_vec()))
            .expect("purged content can be rebuilt");
        assert!(!removed_again.raw_eq(removed));
    }

    #[test]
    fn empty_candidate_set_preserves_all_tables() {
        let mut heap = EvalHeap::new();
        let _string = heap
            .alloc_string(NixString::from_bytes(b"string".to_vec()))
            .expect("string allocates");
        let _path = heap
            .alloc_path(NixString::from_bytes(b"path".to_vec()))
            .expect("path allocates");

        let report = heap.purge_weak_hash_cons_candidates(&[]);

        assert_eq!(report.string.before, report.string.after);
        assert_eq!(report.path.before, report.path.after);
        assert_eq!(report.string.retained.candidates_removed, 0);
        assert_eq!(report.path.retained.candidates_removed, 0);
    }
}
