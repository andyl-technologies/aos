//! Declares the actual immutable String/Value key lookup's fixed demand.
//!
//! The operation is already reached by object_before_child. This module runs no
//! lookup, allocation or parser and changes no ordinary parsing behavior. All
//! helpers below feed compile-time items; reading the DATA is not admission.

use serde_json::{Map, Value};
use std::{collections::BTreeMap, mem::size_of};

#[path = "lookup/compare.rs"]
mod compare;
#[path = "lookup/geometry.rs"]
mod geometry;
#[path = "lookup/search.rs"]
mod search;

/// Sums source windows at compile time, preserving an unavailable overflow.
const fn total<const N: usize>(values: [usize; N]) -> usize {
    let mut result = 0usize;
    let mut index = 0usize;
    while index < N {
        result = match result.checked_add(values[index]) {
            Some(value) => value,
            None => return usize::MAX,
        };
        index += 1;
    }
    result
}

const TRANSIENT: usize = total([search::TRANSIENT, compare::TRANSIENT]);
const SCRATCH: usize = total([search::SCRATCH, compare::SCRATCH]);

// The two actual serde_json1.0.150 MapImpl alternatives are pinned. Under the
// preserve_order branch, IndexMap2.14.0 contains Core; Core has BOTH a Vec of
// entries and HashTable<usize>. HashTable -> RawTable -> RawTableInner includes
// bucket_mask:usize. Those nonoverlapping fields force this lower bound even
// without assuming HashTable's whole layout or its hasher's extent.
// RawVec<T,Global>'s only T-dependent field is zero-sized PhantomData<T>, so the
// actual Vec<Bucket<String,Value>> header equals this concrete Vec header.
const INDEXMAP_MINIMUM: usize = size_of::<Vec<Value>>() + size_of::<usize>();

const SUPPORTED: bool = geometry::SUPPORTED
    && size_of::<Map<String, Value>>() == size_of::<BTreeMap<String, Value>>()
    && size_of::<Map<String, Value>>() < INDEXMAP_MINIMUM
    && TRANSIENT != usize::MAX
    && SCRATCH != usize::MAX;

/// Supplies fixed `[retained, transient, scratch]` demand for strict key lookup.
///
/// The concrete operation is `Map<String, Value>::contains_key(&String)` under
/// the source-pinned ordinary BTreeMap backend. It allocates no backing and
/// borrows the original map/key without cloning or traversing any Value child.
/// T names owned control inputs/initializers/returns; S names borrowed/scalar
/// search, iteration and comparison windows. Loops reuse one fixed set of each
/// nested window, independently of map population, height or string length.
/// This is neither a CPU-work bound nor a physical stack/backend measurement.
///
/// `None` means this supplier DATA is unavailable for the compiled profile.
/// In particular, the pinned IndexMap/hashbrown field lower bound excludes
/// downstream serde_json `preserve_order` unification; equality of public map
/// sizes alone is not the backing proof. Ordinary parsing remains unchanged.
/// Source/compiler/dependency upgrades require a new audit even when public
/// anchors still match. The exact AOS1.98.1/serde_json1.0.150/indexmap2.14.0/
/// hashbrown0.17.1 source pins accompany this supplier's review artifact.
///
/// Callers independently price loading/handling this Option and compose it
/// beside their actual parent/map/key/error owners before admitting work. No
/// error constructor, insertion, allocator, Value ownership or phase permission
/// is supplied by this constant.
pub const STRICT_JSON_KEY_LOOKUP_STORAGE_DATA: Option<[usize; 3]> = if SUPPORTED {
    Some([0, TRANSIENT, SCRATCH])
} else {
    None
};

#[cfg(test)]
#[path = "lookup/tests.rs"]
mod tests;
