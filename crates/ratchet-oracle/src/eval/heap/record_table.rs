//! Address-indexed side table of typed heap records.
//!
//! Runtime [`Value`] words carry a bare opaque [`HeapObject`] pointer; the
//! typed Rust payload behind that pointer lives in a side table, not in the
//! bump arena. Resolving a pointer back to its record is therefore on the
//! evaluator's hottest path - every `get_string`/`get_list`/`get_attrs`/
//! `get_thunk`, every hash-cons collision probe, and every generational-GC
//! address lookup funnels through it.
//!
//! A plain `Vec<HeapRecord>` forces that resolution to be a linear scan over a
//! monotonically growing table (hash-consed strings, lists, and attrsets are
//! never reclaimed), making each dereference `O(n)` and whole-evaluation cost
//! `O(n^2)` - invisible at small scale, catastrophic at `pkgs.linux` scale.
//!
//! [`HeapRecordTable`] pairs the record `Vec` with an address-keyed
//! `HashMap<usize, u32>` (record address -> record index) so resolution is
//! `O(1)`. The map is a strict, always-coherent mirror of the `Vec`: it is
//! updated in lockstep at every insertion ([`HeapRecordTable::push`]) and every
//! tail removal ([`HeapRecordTable::truncate`]), the only two structural
//! mutations the table supports. Record addresses are never relocated once
//! allocated, so no entry is ever rekeyed in place.
//!
//! A worker-region pop truncates the tail and a later bump allocation may reuse
//! a just-freed address for a new record; because `truncate` removes the stale
//! entry before `push` inserts the fresh one, the map always reflects the
//! *current* occupant of every address.
//!
//! ```text
//! records:  [ r0 r1 r2 r3 ]           index: { &r0->0, &r1->1, &r2->2, &r3->3 }
//! truncate(2)                         index: { &r0->0, &r1->1 }
//! push(r4 @ old &r2 address)          index: { &r0->0, &r1->1, &r4->2 }
//! ```

use std::cell::RefCell;
use std::collections::TryReserveError;
use std::collections::hash_map::{Entry, HashMap};
use std::hash::{BuildHasherDefault, Hasher};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

use crate::cache::cutoff::ValueHash;
use crate::value::HeapObject;

use super::HeapRecord;

/// Multiply constant for the `FxHash`-style integer mixer (the 64-bit variant).
///
/// This mirrors the mixer used by the tree-walk select caches; the heap keeps
/// its own copy rather than depending on `tree_walk`, since the heap sits below
/// the evaluator in the module layering.
const ADDRESS_HASH_MULTIPLIER: u64 = 0x51_7c_c1_b7_27_22_0a_95;

/// Rotate applied to the running hash before mixing the address word.
const ADDRESS_HASH_ROTATE: u32 = 5;

/// A minimal `FxHash`-style hasher specialized for heap-record addresses.
///
/// Record addresses are word-aligned pointers, so their low bits are always
/// zero; a multiply-rotate mixer spreads that structure across the full width
/// far more cheaply than the default DoS-resistant `SipHash`. The keys are
/// internal pointer values and never attacker-chosen, so the weaker mixer is
/// safe here.
#[derive(Default)]
struct AddressHasher {
    hash: u64,
}

impl Hasher for AddressHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        // Addresses are mixed through `write_usize`; the byte path is only a
        // correctness fallback and is not reached for `usize` keys.
        for &byte in bytes {
            self.hash = (self.hash.rotate_left(ADDRESS_HASH_ROTATE) ^ u64::from(byte))
                .wrapping_mul(ADDRESS_HASH_MULTIPLIER);
        }
    }

    #[inline]
    fn write_usize(&mut self, value: usize) {
        self.hash = (self.hash.rotate_left(ADDRESS_HASH_ROTATE) ^ value as u64)
            .wrapping_mul(ADDRESS_HASH_MULTIPLIER);
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

/// An address-keyed index over the heap record table.
type AddressIndex = HashMap<usize, u32, BuildHasherDefault<AddressHasher>>;

/// An address-keyed sparse side map of cutoff-cache value hashes.
type ColdHashMap = HashMap<usize, HeapColdHashes, BuildHasherDefault<AddressHasher>>;

/// The cutoff-cache value hashes optionally attached to one heap record.
///
/// These hashes are written only for the small subset of values that become
/// cutoff-cache subjects (imports and other cacheable impure primop results),
/// so they live in a sparse side map keyed by record address rather than inline
/// in every [`HeapRecord`]. Keeping them out of the hot record keeps the record
/// table dense on the resolution path, which touches only [`HeapRecord::object`]
/// and never these fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct HeapColdHashes {
    /// The canonical value hash cached for a reusable heap value.
    value: Option<ValueHash>,
    /// The force-capture value hash cached for a reusable heap value.
    captured: Option<ValueHash>,
}

impl HeapColdHashes {
    /// Returns `true` when neither hash is present, so the entry can be dropped.
    const fn is_empty(self) -> bool {
        self.value.is_none() && self.captured.is_none()
    }
}

/// A `Vec<HeapRecord>` paired with an address-keyed index for `O(1)` lookup.
///
/// The table dereferences to `[HeapRecord]`, so all read-only slice operations
/// (`iter`, indexing, `len`, `get`) and in-place field mutation through
/// [`HeapRecordTable::iter_mut`] work directly. The only structural mutations
/// are [`HeapRecordTable::push`] (append) and [`HeapRecordTable::truncate`]
/// (drop a tail), both of which keep the index coherent.
///
/// # Invariants
///
/// - The index contains exactly one entry per record, keyed by the record's
///   `ptr` address and valued with that record's position in the `Vec`.
/// - A record's `ptr` address is never mutated after insertion, so index
///   entries are never rekeyed; positions shift only when the tail is
///   truncated, and the truncated records' entries are removed with them.
#[derive(Debug)]
pub(super) struct HeapRecordTable {
    records: Vec<HeapRecord>,
    index: AddressIndex,
    cold_hashes: RefCell<ColdHashMap>,
}

impl HeapRecordTable {
    /// Creates an empty record table.
    pub(super) fn new() -> Self {
        Self {
            records: Vec::new(),
            index: AddressIndex::default(),
            cold_hashes: RefCell::new(ColdHashMap::default()),
        }
    }

    /// Appends `record` to the table and indexes it by its address.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the record's address already has a live index
    /// entry, which would mean the arena handed out an address still owned by a
    /// live record - a violation of the unique-live-address contract.
    pub(super) fn push(&mut self, record: HeapRecord) {
        let address = record.ptr.as_ptr() as usize;
        let position = self.records.len();
        debug_assert!(
            position <= u32::MAX as usize,
            "heap record count exceeds the u32 index width"
        );
        self.records.push(record);
        match self.index.entry(address) {
            Entry::Occupied(_) => {
                debug_assert!(false, "pushed a record over a live heap address");
                // Reflect the current occupant even if the invariant is
                // violated in release, so lookups resolve to the newest record.
                self.index.insert(address, position as u32);
            }
            Entry::Vacant(slot) => {
                slot.insert(position as u32);
            }
        }
    }

    /// Drops all records past `len`, removing their index entries.
    ///
    /// This is a no-op if `len` is at least the current length. Because records
    /// are only ever removed from the tail, no surviving record changes
    /// position, so no surviving index entry needs to be rekeyed.
    pub(super) fn truncate(&mut self, len: usize) {
        if len >= self.records.len() {
            return;
        }
        let cold_hashes = self.cold_hashes.get_mut();
        for record in &self.records[len..] {
            let address = record.ptr.as_ptr() as usize;
            self.index.remove(&address);
            cold_hashes.remove(&address);
        }
        self.records.truncate(len);
    }

    /// Returns the cached canonical value hash for the record at `address`.
    ///
    /// Returns `None` when the address has no record or its record carries no
    /// cached canonical hash.
    #[inline]
    pub(super) fn cold_value_hash(&self, address: usize) -> Option<ValueHash> {
        self.cold_hashes.borrow().get(&address)?.value
    }

    /// Returns the cached force-capture value hash for the record at `address`.
    ///
    /// Returns `None` when the address has no record or its record carries no
    /// cached force-capture hash.
    #[inline]
    pub(super) fn cold_captured_value_hash(&self, address: usize) -> Option<ValueHash> {
        self.cold_hashes.borrow().get(&address)?.captured
    }

    /// Sets (or clears, when `hash` is `None`) the canonical value hash for the
    /// record at `address`.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `address` does not name a live record, which
    /// would leak a cold-hash entry past its record's lifetime.
    pub(super) fn set_cold_value_hash(&self, address: usize, hash: Option<ValueHash>) {
        debug_assert!(
            hash.is_none() || self.index.contains_key(&address),
            "cold value hash written for an address with no live record"
        );
        self.write_cold_hash(address, |slot| slot.value = hash);
    }

    /// Sets (or clears, when `hash` is `None`) the force-capture value hash for
    /// the record at `address`.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `address` does not name a live record, which
    /// would leak a cold-hash entry past its record's lifetime.
    pub(super) fn set_cold_captured_value_hash(&self, address: usize, hash: Option<ValueHash>) {
        debug_assert!(
            hash.is_none() || self.index.contains_key(&address),
            "cold captured value hash written for an address with no live record"
        );
        self.write_cold_hash(address, |slot| slot.captured = hash);
    }

    /// Clears both cached hashes for the record at `address`.
    ///
    /// Used by minor-GC field rewrites that reset a relocated record's cached
    /// hashes before the collector recomputes them.
    pub(super) fn clear_cold_hashes(&mut self, address: usize) {
        self.cold_hashes.get_mut().remove(&address);
    }

    /// Applies `mutate` to the cold-hash entry for `address`, dropping the entry
    /// when it becomes empty so the map stays sparse.
    fn write_cold_hash(&self, address: usize, mutate: impl FnOnce(&mut HeapColdHashes)) {
        let mut cold_hashes = self.cold_hashes.borrow_mut();
        let mut slot = cold_hashes.get(&address).copied().unwrap_or_default();
        mutate(&mut slot);
        if slot.is_empty() {
            cold_hashes.remove(&address);
        } else {
            cold_hashes.insert(address, slot);
        }
    }

    /// Reserves capacity for at least `additional` more records and index
    /// entries.
    ///
    /// # Errors
    ///
    /// Returns [`TryReserveError`] if either the record `Vec` or the address
    /// index cannot grow to hold the additional entries.
    pub(super) fn try_reserve_exact(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.records.try_reserve_exact(additional)?;
        self.index.try_reserve(additional)?;
        Ok(())
    }

    /// Returns the position of the record at `address`, or `None`.
    ///
    /// This is the `O(1)` core of every heap-pointer resolution.
    #[inline]
    pub(super) fn index_of_address(&self, address: usize) -> Option<usize> {
        self.index.get(&address).map(|&position| position as usize)
    }

    /// Returns the record stored at `address`, or `None`.
    #[inline]
    pub(super) fn record_at_address(&self, address: usize) -> Option<&HeapRecord> {
        let position = self.index_of_address(address)?;
        self.records.get(position)
    }

    /// Returns the record behind `ptr`, or `None` if no record owns it.
    #[inline]
    pub(super) fn find(&self, ptr: NonNull<HeapObject>) -> Option<&HeapRecord> {
        self.record_at_address(ptr.as_ptr() as usize)
    }
}

impl Deref for HeapRecordTable {
    type Target = [HeapRecord];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

impl<'a> IntoIterator for &'a HeapRecordTable {
    type Item = &'a HeapRecord;
    type IntoIter = std::slice::Iter<'a, HeapRecord>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.records.iter()
    }
}

impl<'a> IntoIterator for &'a mut HeapRecordTable {
    type Item = &'a mut HeapRecord;
    type IntoIter = std::slice::IterMut<'a, HeapRecord>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.records.iter_mut()
    }
}

impl DerefMut for HeapRecordTable {
    /// Yields the records as a mutable slice for in-place field mutation.
    ///
    /// A slice cannot add or remove records, so structural mutation still has
    /// to go through [`HeapRecordTable::push`] or [`HeapRecordTable::truncate`]
    /// and the index stays coherent. Callers must not overwrite a record's
    /// `ptr` field, which would desynchronize the address index from the record
    /// it keys; every other field is safe to mutate in place.
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.records
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;

    use super::super::{
        EvalHeap, EvalThunk, HeapAllocationDomain, HeapObjectValue, HeapRecord, HeapRecordLayout,
    };
    use super::HeapRecordTable;
    use crate::compile::IrId;
    use crate::heap::HeapGeneration;
    use crate::string::NixString;
    use crate::value::HeapObject;
    use std::ptr::NonNull;

    /// Builds a synthetic record at a fixed address, tagged by `touch` so tests
    /// can tell distinct records apart through the read-back `last_touch_epoch`.
    ///
    /// The table only ever reads `record.ptr` as an address, never dereferences
    /// it, so a fabricated non-null pointer is a valid stand-in here.
    fn record_at(address: usize, touch: u64) -> HeapRecord {
        let ptr = NonNull::new(address as *mut HeapObject).expect("address is non-zero");
        HeapRecord {
            ptr,
            layout: HeapRecordLayout {
                size_bytes: 0,
                align: 1,
            },
            structural_hash: None,
            allocation_domain: HeapAllocationDomain::Worker,
            generation: HeapGeneration::Young,
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch: Cell::new(touch),
            object: HeapObjectValue::Thunk(Arc::new(EvalThunk::new(IrId::new(0)))),
        }
    }

    /// The index resolves each pushed record to its own position, and a tail
    /// truncation removes exactly the popped entries while leaving the survivors
    /// resolvable.
    #[test]
    fn push_and_truncate_keep_the_index_coherent() {
        let mut table = HeapRecordTable::new();
        table.push(record_at(0x1000, 1));
        table.push(record_at(0x2000, 2));
        table.push(record_at(0x3000, 3));

        assert_eq!(table.index_of_address(0x1000), Some(0));
        assert_eq!(table.index_of_address(0x2000), Some(1));
        assert_eq!(table.index_of_address(0x3000), Some(2));

        table.truncate(1);

        assert_eq!(table.index_of_address(0x1000), Some(0));
        assert_eq!(table.index_of_address(0x2000), None);
        assert_eq!(table.index_of_address(0x3000), None);
        assert_eq!(table.len(), 1);
    }

    /// A freed address that is later reused resolves to the new record, never
    /// the stale one: the truncation removed the old entry and the reinsert
    /// re-points the address at the current occupant.
    #[test]
    fn freed_then_reused_address_resolves_to_the_new_record() {
        let mut table = HeapRecordTable::new();
        table.push(record_at(0x1000, 10));
        table.push(record_at(0x2000, 20));

        table.truncate(1);
        assert_eq!(table.index_of_address(0x2000), None);

        // Reuse the just-freed address for a brand-new record.
        table.push(record_at(0x2000, 99));
        assert_eq!(table.index_of_address(0x2000), Some(1));
        let reused = table
            .record_at_address(0x2000)
            .expect("reused address resolves");
        assert_eq!(
            reused.last_touch_epoch.get(),
            99,
            "index resolved the reused address to the stale record"
        );
        // The untouched survivor is unaffected.
        let survivor = table.record_at_address(0x1000).expect("survivor resolves");
        assert_eq!(survivor.last_touch_epoch.get(), 10);
    }

    /// Every record stays resolvable to its own content after the table has
    /// grown well past the point where a linear scan would dominate, exercising
    /// the address index across many live records through the real heap API.
    #[test]
    fn get_string_round_trips_after_many_allocations() {
        let mut heap = EvalHeap::new();
        let mut allocated = Vec::new();
        for index in 0..500u32 {
            let bytes = format!("round-trip-value-{index}").into_bytes();
            let value = heap
                .alloc_string(NixString::from_bytes(bytes.clone()))
                .expect("string allocation succeeds");
            allocated.push((value, bytes));
        }
        for (value, bytes) in &allocated {
            let resolved = heap.get_string(*value).expect("record resolves");
            assert_eq!(resolved, &NixString::from_bytes(bytes.clone()));
        }
    }

    /// A worker-region pop removes the popped records' index entries, so the
    /// freed heap pointer no longer resolves through the real heap API.
    #[test]
    fn worker_region_pop_removes_the_index_entry() {
        let mut heap = EvalHeap::new();
        let mark = heap.worker_region_mark().expect("open worker region");
        let thunk = heap
            .alloc_thunk(EvalThunk::new(IrId::new(1)))
            .expect("thunk allocation succeeds");
        assert!(heap.get_thunk(thunk).is_ok());

        heap.pop_worker_region_if_disconnected(mark)
            .expect("disconnected worker region pops");

        assert!(
            heap.get_thunk(thunk).is_err(),
            "index still resolved a truncated record's address"
        );
    }
}
