//! Prevalidated retirement of flat immutable source stores after packed publication.
//!
//! Preparation inventories every string, path, list, and attrset allocation
//! while the mutator is suspended. Publication keeps this inventory alive
//! through root and retained-edge healing plus the zero-source-alias audit.
//! Only then does commit replace the three source registries, retire their
//! typed allocations, and advise pages whose arena liveness reached zero.

use std::ptr::NonNull;

use thiserror::Error;

use crate::heap::flat::FlatObjectKind;
use crate::value::HeapObject;
use crate::value::compressed::{CandidateCScalarError, CandidateCScalarRetirementReport};

use super::EvalHeap;

/// One complete immutable-source retirement inventory.
#[derive(Debug)]
pub(crate) struct PreparedPackedSourceRetirement {
    entries: Vec<PackedSourceRetirementEntry>,
    values: usize,
    lists: usize,
    attrs: usize,
}

#[derive(Clone, Copy, Debug)]
struct PackedSourceRetirementEntry {
    ptr: NonNull<HeapObject>,
    kind: FlatObjectKind,
}

/// Result of retiring one packed rotation's old immutable source stores.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PackedSourceRetirementReport {
    /// Typed allocations successfully retired from the arena ledger.
    pub(crate) retired_objects: usize,
    /// Unexpected typed-retirement failures.
    ///
    /// Complete store prevalidation makes this zero for every successful
    /// transaction; the field remains explicit in telemetry.
    pub(crate) failed_objects: usize,
    /// Zero-liveness pages considered for advice.
    pub(crate) candidate_pages: usize,
    /// Pages for which the operating system accepted advice.
    pub(crate) advised_pages: usize,
    /// Whether the arena or operating system rejected page advice.
    pub(crate) advice_failed: bool,
}

impl EvalHeap {
    /// Inventories every flat immutable source allocation without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`PackedSourceRetirementError`] for a shared heap, population
    /// overflow, allocation failure, or an object in the wrong typed store.
    pub(crate) fn prepare_packed_source_retirement(
        &self,
    ) -> Result<PreparedPackedSourceRetirement, PackedSourceRetirementError> {
        if self.shared.is_some() {
            return Err(PackedSourceRetirementError::SharedHeap);
        }
        let values = self.flat.live_len();
        let lists = self.flat_lists.live_len();
        let attrs = self.flat_attrs.live_len();
        let population = values
            .checked_add(lists)
            .and_then(|count| count.checked_add(attrs))
            .ok_or(PackedSourceRetirementError::PopulationOverflow)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(population).map_err(|_| {
            PackedSourceRetirementError::AllocationFailed {
                entries: population,
            }
        })?;
        for object in self.flat.iter() {
            let kind = object.object().kind();
            if !matches!(kind, FlatObjectKind::String | FlatObjectKind::Path) {
                return Err(PackedSourceRetirementError::UnexpectedKind {
                    expected: "string/path",
                    actual: kind,
                });
            }
            entries.push(PackedSourceRetirementEntry {
                ptr: object.ptr(),
                kind,
            });
        }
        for object in self.flat_lists.iter() {
            let kind = object.object().kind();
            if kind != FlatObjectKind::List {
                return Err(PackedSourceRetirementError::UnexpectedKind {
                    expected: "list",
                    actual: kind,
                });
            }
            entries.push(PackedSourceRetirementEntry {
                ptr: object.ptr(),
                kind,
            });
        }
        for object in self.flat_attrs.iter() {
            let kind = object.object().kind();
            if kind != FlatObjectKind::Attrs {
                return Err(PackedSourceRetirementError::UnexpectedKind {
                    expected: "attrs",
                    actual: kind,
                });
            }
            entries.push(PackedSourceRetirementEntry {
                ptr: object.ptr(),
                kind,
            });
        }
        Ok(PreparedPackedSourceRetirement {
            entries,
            values,
            lists,
            attrs,
        })
    }

    /// Retires a source inventory after publication and zero-alias validation.
    ///
    /// Population, exact identity, and every typed store are validated before
    /// mutation. The returned exclusive store tokens then retire all entries
    /// without a fallible step before empty registry storage is released.
    ///
    /// # Errors
    ///
    /// Returns [`PackedSourceRetirementError`] when an immutable source store
    /// changed after preparation, an immutable typed registry fails complete
    /// prevalidation, or a boxed-scalar registry/hash-cons entry is invalid.
    /// Every error leaves all source stores unchanged.
    pub(crate) fn retire_packed_sources_atomically(
        &mut self,
        prepared: PreparedPackedSourceRetirement,
    ) -> Result<
        (
            PackedSourceRetirementReport,
            CandidateCScalarRetirementReport,
        ),
        PackedSourceRetirementError,
    > {
        let current = (
            self.flat.live_len(),
            self.flat_lists.live_len(),
            self.flat_attrs.live_len(),
        );
        let expected = (prepared.values, prepared.lists, prepared.attrs);
        if current != expected {
            return Err(PackedSourceRetirementError::PopulationChanged { expected, current });
        }

        let mut inventory_index = 0usize;
        for current in self.flat.iter() {
            require_inventory_entry(
                &prepared,
                inventory_index,
                current.ptr(),
                current.object().kind(),
            )?;
            inventory_index = inventory_index.saturating_add(1);
        }
        for current in self.flat_lists.iter() {
            require_inventory_entry(
                &prepared,
                inventory_index,
                current.ptr(),
                current.object().kind(),
            )?;
            inventory_index = inventory_index.saturating_add(1);
        }
        for current in self.flat_attrs.iter() {
            require_inventory_entry(
                &prepared,
                inventory_index,
                current.ptr(),
                current.object().kind(),
            )?;
            inventory_index = inventory_index.saturating_add(1);
        }

        // Every fallible validation across all five source stores completes
        // before the first commit. The tokens borrow disjoint stores
        // exclusively, so publication cannot change any validated registry
        // before the allocation-free commits below.
        let scalars = self.compressed_scalars.prepare_retire_all_boxed()?;
        let values = self.flat.prepare_retire_all_live()?;
        let lists = self.flat_lists.prepare_retire_all_live()?;
        let attrs = self.flat_attrs.prepare_retire_all_live()?;
        let scalar_report = scalars.commit();
        let retired_objects = values
            .commit_and_reset()
            .saturating_add(lists.commit_and_reset())
            .saturating_add(attrs.commit_and_reset());

        let mut report = PackedSourceRetirementReport {
            retired_objects,
            ..PackedSourceRetirementReport::default()
        };
        let advice = self.flat_arena.advise_zero_liveness_pages();
        match advice {
            Some(Ok(advice)) => {
                report.candidate_pages = advice.candidate_pages();
                report.advised_pages = advice.applied_pages();
            }
            Some(Err(_)) => report.advice_failed = true,
            None => {}
        }
        Ok((report, scalar_report))
    }

    /// Retires immutable sources through the all-source atomic commit path.
    ///
    /// This compatibility seam is used by focused immutable-store tests. Any
    /// boxed scalar cells present in the heap are retired in the same validated
    /// transaction.
    ///
    /// # Errors
    ///
    /// Returns [`PackedSourceRetirementError`] if any immutable or scalar
    /// source store fails validation. No source store changes on an error.
    pub(crate) fn retire_packed_source(
        &mut self,
        prepared: PreparedPackedSourceRetirement,
    ) -> Result<PackedSourceRetirementReport, PackedSourceRetirementError> {
        self.retire_packed_sources_atomically(prepared)
            .map(|(immutable, _)| immutable)
    }
}

fn require_inventory_entry(
    prepared: &PreparedPackedSourceRetirement,
    index: usize,
    ptr: NonNull<HeapObject>,
    kind: FlatObjectKind,
) -> Result<(), PackedSourceRetirementError> {
    let Some(expected) = prepared.entries.get(index) else {
        return Err(PackedSourceRetirementError::InventoryChanged);
    };
    if expected.ptr != ptr || expected.kind != kind {
        return Err(PackedSourceRetirementError::InventoryChanged);
    }
    Ok(())
}

/// Preparing or committing immutable source retirement failed.
#[derive(Debug, Error)]
pub(crate) enum PackedSourceRetirementError {
    /// Packed rotations are serial-only.
    #[error("packed source retirement requires a serial heap")]
    SharedHeap,
    /// Source population arithmetic exceeded `usize`.
    #[error("packed source retirement population overflow")]
    PopulationOverflow,
    /// Exact inventory storage could not be reserved.
    #[error("packed source retirement could not reserve {entries} entries")]
    AllocationFailed {
        /// Exact source population.
        entries: usize,
    },
    /// A typed source store contained an impossible object kind.
    #[error("packed source retirement expected {expected}, found {actual:?}")]
    UnexpectedKind {
        /// Required store kind.
        expected: &'static str,
        /// Observed object kind.
        actual: FlatObjectKind,
    },
    /// The source stores changed after the inventory was prepared.
    #[error(
        "packed source population changed after preparation: expected {expected:?}, current {current:?}"
    )]
    PopulationChanged {
        /// Prepared `(string/path, list, attrs)` populations.
        expected: (usize, usize, usize),
        /// Current populations.
        current: (usize, usize, usize),
    },
    /// An exact source allocation changed while preserving aggregate counts.
    #[error("packed source retirement inventory changed after preparation")]
    InventoryChanged,
    /// A current typed source store failed complete prevalidation.
    #[error("packed source retirement store validation failed: {0}")]
    Flat(#[from] crate::heap::flat::FlatObjectError),
    /// A boxed-scalar source store failed complete prevalidation.
    #[error("packed scalar source retirement failed: {0}")]
    Scalar(#[from] CandidateCScalarError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::list::NixList;
    use crate::string::NixString;

    #[test]
    fn complete_retirement_rejects_old_words_and_reopens_same_domain() {
        let mut heap = EvalHeap::new();
        let string = heap
            .alloc_string(NixString::from_bytes(b"source".to_vec()))
            .expect("source string allocates");
        let list = heap
            .alloc_list(NixList::new(vec![string]))
            .expect("source list allocates");
        let scalar = heap
            .candidate_c_encode_int(i64::MAX)
            .expect("boxed scalar allocates");
        let source_domain = string
            .word()
            .arena_domain()
            .expect("source string is indexed");
        let prepared = heap
            .prepare_packed_source_retirement()
            .expect("source retirement prepares");

        let report = heap
            .retire_packed_source(prepared)
            .expect("source retirement commits");

        assert_eq!(report.retired_objects, 2);
        assert_eq!(report.failed_objects, 0);
        assert!(heap.get_string(string).is_err());
        assert!(heap.get_list(list).is_err());
        assert!(heap.candidate_c_decode_int(scalar).is_err());
        let replacement = heap
            .alloc_string(NixString::from_bytes(b"replacement".to_vec()))
            .expect("replacement string allocates");
        assert_eq!(replacement.word().arena_domain(), Some(source_domain));
        assert_eq!(
            heap.get_string(replacement)
                .expect("replacement resolves")
                .bytes(),
            b"replacement"
        );
    }

    #[test]
    fn population_change_rejects_before_any_retirement() {
        let mut heap = EvalHeap::new();
        let first = heap
            .alloc_string(NixString::from_bytes(b"first".to_vec()))
            .expect("first string allocates");
        let scalar = heap
            .candidate_c_encode_int(i64::MAX)
            .expect("boxed scalar allocates");
        let prepared = heap
            .prepare_packed_source_retirement()
            .expect("source retirement prepares");
        let second = heap
            .alloc_string(NixString::from_bytes(b"second".to_vec()))
            .expect("second string allocates");

        assert!(matches!(
            heap.retire_packed_source(prepared),
            Err(PackedSourceRetirementError::PopulationChanged { .. })
        ));
        assert_eq!(
            heap.get_string(first).expect("first remains live").bytes(),
            b"first"
        );
        assert_eq!(
            heap.get_string(second)
                .expect("second remains live")
                .bytes(),
            b"second"
        );
        assert_eq!(
            heap.candidate_c_decode_int(scalar)
                .expect("scalar remains live"),
            i64::MAX
        );
    }
}
