//! Hash-cons table support for immutable runtime values.
//!
//! A hash-cons table stores candidate values by an already-computed structural
//! hash. Hashes are lookup accelerators only: callers must still compare the
//! candidate payloads before reusing an existing value.
//!
//! ```text
//! structural hash -> [candidate value, candidate value, ...]
//! lookup          -> bucket scan with caller-owned equality confirmation
//! ```

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

static NEXT_HASH_CONS_TABLE_ID: AtomicU64 = AtomicU64::new(1);

/// A hash-cons table operation failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HashConsError {
    /// A bucket length overflowed while reserving another value slot.
    #[error("hash-cons bucket length overflow")]
    BucketLengthOverflow,
    /// The table could not reserve space for another hash bucket.
    #[error("hash-cons table failed to reserve {entries} buckets")]
    TableAllocationFailed {
        /// The requested bucket count.
        entries: usize,
    },
    /// A bucket could not reserve space for another candidate value.
    #[error("hash-cons bucket failed to reserve {entries} entries")]
    BucketAllocationFailed {
        /// The requested bucket entry count.
        entries: usize,
    },
}

/// Stores hash-cons candidates in buckets keyed by structural hash.
#[derive(Debug)]
pub struct HashConsTable<K, V> {
    table_id: u64,
    buckets: HashMap<K, HashConsBucket<V>>,
}

/// Reserves one candidate slot in a [`HashConsTable`].
#[derive(Debug)]
pub struct HashConsSlot<K> {
    table_id: u64,
    key: K,
}

/// Storage removed by one committed-candidate retention pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HashConsRetainReport {
    /// Committed candidate handles removed from bucket vectors.
    pub candidates_removed: usize,
    /// Empty buckets removed from the outer table.
    pub buckets_removed: usize,
    /// Candidate-vector capacity released across retained buckets.
    pub candidate_capacity_released: usize,
    /// Outer hash-table capacity released by shrinking after retention.
    pub bucket_capacity_released: usize,
}

/// The result of probing a hash-cons table for a copyable runtime handle.
#[derive(Debug)]
pub enum HashConsReservation<K, V> {
    /// An equality-confirmed candidate already exists in the table.
    Existing(V),
    /// No candidate matched, and the table reserved a slot for insertion.
    Vacant(HashConsSlot<K>),
}

#[derive(Clone, Debug)]
struct HashConsBucket<V> {
    values: Vec<V>,
    reserved: usize,
}

impl<V> HashConsBucket<V> {
    fn new() -> Self {
        Self {
            values: Vec::new(),
            reserved: 0,
        }
    }

    fn as_slice(&self) -> &[V] {
        self.values.as_slice()
    }

    fn reserve_slot(&mut self) -> Result<(), HashConsError> {
        let reserved = self
            .reserved
            .checked_add(1)
            .ok_or(HashConsError::BucketLengthOverflow)?;
        let entries = self
            .values
            .len()
            .checked_add(reserved)
            .ok_or(HashConsError::BucketLengthOverflow)?;
        self.values
            .try_reserve_exact(reserved)
            .map_err(|_| HashConsError::BucketAllocationFailed { entries })?;
        self.reserved = reserved;
        Ok(())
    }

    fn push_reserved(&mut self, value: V) -> bool {
        if self.reserved == 0 || self.values.len() == self.values.capacity() {
            return false;
        }
        self.reserved -= 1;
        self.values.push(value);
        true
    }

    fn cancel_reserved(&mut self) -> bool {
        if self.reserved == 0 {
            return false;
        }
        self.reserved -= 1;
        true
    }

    fn clone_committed(&self) -> Self
    where
        V: Clone,
    {
        Self {
            values: self.values.clone(),
            reserved: 0,
        }
    }
}

impl<K, V> HashConsTable<K, V> {
    /// Creates an empty hash-cons table.
    pub fn new() -> Self {
        Self {
            table_id: next_hash_cons_table_id(),
            buckets: HashMap::new(),
        }
    }

    /// Returns whether the table has no hash buckets.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Returns the number of hash buckets currently stored in the table.
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Returns hash-map and candidate-vector length/capacity counts.
    ///
    /// The tuple is `(buckets, bucket capacity, candidates, candidate
    /// capacity)`. Multiplying the capacities by the corresponding key,
    /// bucket, and value representation sizes gives a lower-bound structural
    /// byte attribution; allocator and hash-table control bytes are separate.
    pub fn storage_counts(&self) -> (usize, usize, usize, usize) {
        let candidates = self
            .buckets
            .values()
            .map(|bucket| bucket.values.len())
            .sum();
        let candidate_capacity = self
            .buckets
            .values()
            .map(|bucket| bucket.values.capacity())
            .sum();
        (
            self.buckets.len(),
            self.buckets.capacity(),
            candidates,
            candidate_capacity,
        )
    }
}

impl<K, V> Clone for HashConsTable<K, V>
where
    K: Clone,
    V: Clone,
{
    fn clone(&self) -> Self {
        let mut buckets = self.buckets.clone();
        for bucket in buckets.values_mut() {
            *bucket = bucket.clone_committed();
        }
        buckets.retain(|_key, bucket| !bucket.values.is_empty());
        Self {
            table_id: next_hash_cons_table_id(),
            buckets,
        }
    }
}

impl<K, V> Default for HashConsTable<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> HashConsTable<K, V>
where
    K: Eq + Hash,
{
    /// Returns the candidate bucket for `key`.
    pub fn bucket(&self, key: &K) -> Option<&[V]> {
        self.buckets.get(key).map(HashConsBucket::as_slice)
    }

    /// Iterates all committed values with their bucket key and bucket-local index.
    ///
    /// Outstanding reserved slots are not yielded because they do not yet hold
    /// runtime values. The outer iteration order is an implementation detail of
    /// the underlying hash table; callers that expose stable labels must sort by
    /// the returned key and index.
    pub fn committed_entries(&self) -> impl Iterator<Item = (&K, usize, &V)> {
        self.buckets
            .iter()
            .flat_map(|(key, bucket)| {
                bucket
                    .values
                    .iter()
                    .enumerate()
                    .map(move |entry| (key, entry))
            })
            .map(|(key, (index, value))| (key, index, value))
    }

    /// Retains committed candidates selected by `keep` and shrinks their indexes.
    ///
    /// Outstanding reservations are preserved. A bucket with no committed
    /// candidates remains present while it owns a reservation, so an existing
    /// [`HashConsSlot`] can still be committed or cancelled after this pass.
    /// Callers that use this for weak interning must remove dead handles before
    /// invalidating the objects they name.
    pub fn retain_committed(&mut self, mut keep: impl FnMut(&V) -> bool) -> HashConsRetainReport {
        let buckets_before = self.buckets.len();
        let bucket_capacity_before = self.buckets.capacity();
        let mut candidates_removed = 0usize;
        let mut candidate_capacity_released = 0usize;
        for bucket in self.buckets.values_mut() {
            let len_before = bucket.values.len();
            let capacity_before = bucket.values.capacity();
            bucket.values.retain(|value| keep(value));
            candidates_removed =
                candidates_removed.saturating_add(len_before.saturating_sub(bucket.values.len()));
            bucket
                .values
                .shrink_to(bucket.values.len().saturating_add(bucket.reserved));
            candidate_capacity_released = candidate_capacity_released
                .saturating_add(capacity_before.saturating_sub(bucket.values.capacity()));
        }
        self.buckets
            .retain(|_key, bucket| !bucket.values.is_empty() || bucket.reserved != 0);
        self.buckets.shrink_to_fit();
        HashConsRetainReport {
            candidates_removed,
            buckets_removed: buckets_before.saturating_sub(self.buckets.len()),
            candidate_capacity_released,
            bucket_capacity_released: bucket_capacity_before
                .saturating_sub(self.buckets.capacity()),
        }
    }

    /// Rebuilds every committed value under a caller-computed key.
    ///
    /// Outstanding reservations are deliberately omitted, matching
    /// [`Self::committed_entries`]. The returned table is independent of
    /// `self`, so callers can finish every fallible key computation and bucket
    /// reservation before atomically replacing a live table.
    ///
    /// # Errors
    ///
    /// Returns an error from `key_for` or a converted [`HashConsError`] if the
    /// rebuilt table cannot reserve a bucket or candidate slot.
    ///
    /// # Panics
    ///
    /// Panics only if an internal table invariant loses a freshly reserved
    /// slot before its immediately following insertion.
    pub fn try_rekey_committed<E>(
        &self,
        mut key_for: impl FnMut(&V) -> Result<K, E>,
    ) -> Result<Self, E>
    where
        K: Clone,
        V: Clone,
        E: From<HashConsError>,
    {
        let mut rebuilt = Self::new();
        for (_old_key, _index, value) in self.committed_entries() {
            let slot = rebuilt.reserve_slot(key_for(value)?)?;
            if !rebuilt.push_reserved(slot, value.clone()) {
                unreachable!("fresh hash-cons reservation disappeared");
            }
        }
        Ok(rebuilt)
    }

    /// Returns the first candidate whose predicate confirms equality.
    ///
    /// The predicate is where callers compare the candidate payload with the
    /// value being interned. Hash collisions therefore remain ordinary
    /// non-matches instead of being silently reused.
    ///
    /// # Errors
    ///
    /// Returns any error produced by `matches`.
    pub fn try_find<E>(
        &self,
        key: &K,
        mut matches: impl FnMut(&V) -> Result<bool, E>,
    ) -> Result<Option<&V>, E> {
        let Some(bucket) = self.buckets.get(key) else {
            return Ok(None);
        };
        for candidate in bucket.as_slice() {
            if matches(candidate)? {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    /// Returns an existing candidate or reserves a slot for a missing value.
    ///
    /// The predicate confirms equality for every candidate in the matching hash
    /// bucket. When it finds a match, the copyable runtime handle is returned
    /// without mutating the table. When it finds no match, the table reserves one
    /// candidate slot and returns a token that must be passed to
    /// [`HashConsTable::push_reserved`] after allocation, or to
    /// [`HashConsTable::cancel_reserved`] if allocation fails.
    ///
    /// # Errors
    ///
    /// Returns any error produced by `matches`. Returns [`HashConsError`] via
    /// `E::from` if the table cannot reserve a bucket or candidate slot.
    pub fn try_get_or_reserve<E>(
        &mut self,
        key: K,
        matches: impl FnMut(&V) -> Result<bool, E>,
    ) -> Result<HashConsReservation<K, V>, E>
    where
        K: Clone,
        V: Copy,
        E: From<HashConsError>,
    {
        if let Some(existing) = self.try_find(&key, matches)?.copied() {
            return Ok(HashConsReservation::Existing(existing));
        }
        Ok(HashConsReservation::Vacant(self.reserve_slot(key)?))
    }

    /// Reserves one additional candidate slot for `key`.
    ///
    /// Callers use this before allocating the value that will be pushed into
    /// the bucket. The returned slot token is consumed by
    /// [`HashConsTable::push_reserved`], so public callers cannot push without
    /// first reserving. If allocation fails before the value is pushed, pass the
    /// token to [`HashConsTable::cancel_reserved`] to release the outstanding
    /// reservation. The table tracks outstanding slots, so multiple unfilled
    /// reservations for the same key still reserve enough capacity for each
    /// later push.
    ///
    /// # Errors
    ///
    /// Returns [`HashConsError::BucketLengthOverflow`] if the selected bucket
    /// length cannot represent one more entry. Returns
    /// [`HashConsError::TableAllocationFailed`] or
    /// [`HashConsError::BucketAllocationFailed`] if the table or bucket cannot
    /// reserve the requested capacity.
    pub fn reserve_slot(&mut self, key: K) -> Result<HashConsSlot<K>, HashConsError>
    where
        K: Clone,
    {
        if let Some(bucket) = self.buckets.get_mut(&key) {
            bucket.reserve_slot()?;
            return Ok(HashConsSlot {
                table_id: self.table_id,
                key,
            });
        }

        self.buckets
            .try_reserve(1)
            .map_err(|_| HashConsError::TableAllocationFailed {
                entries: self.buckets.len().saturating_add(1),
            })?;
        let mut bucket = HashConsBucket::new();
        bucket.reserve_slot()?;
        self.buckets.insert(key.clone(), bucket);
        Ok(HashConsSlot {
            table_id: self.table_id,
            key,
        })
    }

    /// Pushes a value into a reserved bucket.
    ///
    /// Returns `false` when the slot came from a different table, no bucket
    /// exists for the slot key, or no outstanding reservation remains for that
    /// key.
    pub fn push_reserved(&mut self, slot: HashConsSlot<K>, value: V) -> bool {
        if slot.table_id != self.table_id {
            return false;
        }
        let Some(bucket) = self.buckets.get_mut(&slot.key) else {
            return false;
        };
        bucket.push_reserved(value)
    }

    /// Releases a reserved slot without inserting a value.
    ///
    /// Call this when allocation fails after [`HashConsTable::reserve_slot`] or
    /// [`HashConsTable::try_get_or_reserve`] returned a vacant slot. Returns
    /// `false` when the slot did not originate from this table, the key no
    /// longer has a bucket, or no outstanding reservation remains for the key.
    pub fn cancel_reserved(&mut self, slot: HashConsSlot<K>) -> bool {
        if slot.table_id != self.table_id {
            return false;
        }
        let remove_bucket = {
            let Some(bucket) = self.buckets.get_mut(&slot.key) else {
                return false;
            };
            if !bucket.cancel_reserved() {
                return false;
            }
            bucket.values.is_empty() && bucket.reserved == 0
        };
        if remove_bucket {
            self.buckets.remove(&slot.key);
        }
        true
    }
}

fn next_hash_cons_table_id() -> u64 {
    NEXT_HASH_CONS_TABLE_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_starts_empty() {
        let table = HashConsTable::<u8, u8>::new();

        assert!(table.is_empty());
        assert_eq!(table.bucket_count(), 0);
        assert_eq!(table.bucket(&1), None);
    }

    #[test]
    fn reserved_values_are_visible_in_key_bucket() {
        let mut table = HashConsTable::<u8, &str>::new();

        let first_slot = table.reserve_slot(7).expect("first slot reserves");
        assert!(table.push_reserved(first_slot, "first"));
        let second_slot = table.reserve_slot(7).expect("second slot reserves");
        assert!(table.push_reserved(second_slot, "second"));

        assert_eq!(table.bucket_count(), 1);
        assert_eq!(table.bucket(&7), Some(["first", "second"].as_slice()));
    }

    #[test]
    fn separate_keys_keep_separate_buckets() {
        let mut table = HashConsTable::<u8, &str>::new();

        let left_slot = table.reserve_slot(1).expect("left slot reserves");
        assert!(table.push_reserved(left_slot, "left"));
        let right_slot = table.reserve_slot(2).expect("right slot reserves");
        assert!(table.push_reserved(right_slot, "right"));

        assert_eq!(table.bucket_count(), 2);
        assert_eq!(table.bucket(&1), Some(["left"].as_slice()));
        assert_eq!(table.bucket(&2), Some(["right"].as_slice()));
    }

    #[test]
    fn push_with_foreign_reservation_reports_missing_bucket() {
        let mut left = HashConsTable::<u8, &str>::new();
        let mut right = HashConsTable::<u8, &str>::new();

        let slot = left.reserve_slot(7).expect("slot reserves");

        assert!(!right.push_reserved(slot, "value"));
        assert!(right.is_empty());
    }

    #[test]
    fn foreign_slot_with_same_key_does_not_consume_destination_reservation() {
        let mut left = HashConsTable::<u8, &str>::new();
        let mut right = HashConsTable::<u8, &str>::new();

        let left_slot = left.reserve_slot(7).expect("left slot reserves");
        let right_slot = right.reserve_slot(7).expect("right slot reserves");

        assert!(!right.push_reserved(left_slot, "wrong"));
        assert!(right.push_reserved(right_slot, "right"));
        assert_eq!(right.bucket(&7), Some(["right"].as_slice()));
    }

    #[test]
    fn try_find_uses_predicate_to_confirm_candidates() {
        let mut table = HashConsTable::<u8, &str>::new();

        let first_slot = table.reserve_slot(7).expect("first slot reserves");
        assert!(table.push_reserved(first_slot, "left"));
        let second_slot = table.reserve_slot(7).expect("second slot reserves");
        assert!(table.push_reserved(second_slot, "right"));

        let found = table
            .try_find(&7, |candidate| Ok::<bool, ()>(*candidate == "right"))
            .expect("predicate succeeds");
        let missing = table
            .try_find(&7, |candidate| Ok::<bool, ()>(*candidate == "missing"))
            .expect("predicate succeeds");

        assert_eq!(found, Some(&"right"));
        assert_eq!(missing, None);
    }

    #[test]
    fn try_find_propagates_predicate_errors() {
        let mut table = HashConsTable::<u8, &str>::new();

        let slot = table.reserve_slot(7).expect("slot reserves");
        assert!(table.push_reserved(slot, "value"));

        assert_eq!(
            table.try_find(&7, |_| Err::<bool, &str>("predicate failed")),
            Err("predicate failed")
        );
    }

    #[test]
    fn retain_committed_removes_candidates_and_empty_buckets() {
        let mut table = HashConsTable::<u8, u8>::new();
        for (key, value) in [(1, 10), (1, 11), (2, 20)] {
            let slot = table.reserve_slot(key).expect("slot reserves");
            assert!(table.push_reserved(slot, value));
        }

        let report = table.retain_committed(|value| *value == 11);

        assert_eq!(report.candidates_removed, 2);
        assert_eq!(report.buckets_removed, 1);
        assert_eq!(table.bucket(&1), Some([11].as_slice()));
        assert_eq!(table.bucket(&2), None);
    }

    #[test]
    fn retain_committed_preserves_outstanding_reservations() {
        let mut table = HashConsTable::<u8, u8>::new();
        let committed = table.reserve_slot(7).expect("committed slot reserves");
        assert!(table.push_reserved(committed, 1));
        let outstanding = table.reserve_slot(7).expect("outstanding slot reserves");

        let report = table.retain_committed(|_| false);

        assert_eq!(report.candidates_removed, 1);
        assert_eq!(report.buckets_removed, 0);
        assert!(table.push_reserved(outstanding, 2));
        assert_eq!(table.bucket(&7), Some([2].as_slice()));
    }

    #[test]
    fn try_get_or_reserve_returns_existing_candidate() {
        let mut table = HashConsTable::<u8, &str>::new();

        let first_slot = table.reserve_slot(7).expect("first slot reserves");
        assert!(table.push_reserved(first_slot, "left"));
        let second_slot = table.reserve_slot(7).expect("second slot reserves");
        assert!(table.push_reserved(second_slot, "right"));

        let reservation = table
            .try_get_or_reserve(7, |candidate| {
                Ok::<bool, HashConsError>(*candidate == "right")
            })
            .expect("existing candidate is found");

        match reservation {
            HashConsReservation::Existing(value) => assert_eq!(value, "right"),
            HashConsReservation::Vacant(_) => panic!("expected an existing candidate"),
        }
        assert_eq!(table.bucket(&7), Some(["left", "right"].as_slice()));
    }

    #[test]
    fn try_get_or_reserve_returns_vacant_slot_for_missing_candidate() {
        let mut table = HashConsTable::<u8, &str>::new();

        let reservation = table
            .try_get_or_reserve(7, |_| Ok::<bool, HashConsError>(false))
            .expect("vacant slot reserves");

        match reservation {
            HashConsReservation::Existing(_) => panic!("expected a vacant slot"),
            HashConsReservation::Vacant(slot) => {
                assert!(table.push_reserved(slot, "value"));
            }
        }
        assert_eq!(table.bucket(&7), Some(["value"].as_slice()));
    }

    #[derive(Debug, PartialEq, Eq)]
    enum AdmissionTestError {
        HashCons(HashConsError),
        Predicate(&'static str),
    }

    impl From<HashConsError> for AdmissionTestError {
        fn from(error: HashConsError) -> Self {
            Self::HashCons(error)
        }
    }

    #[test]
    fn try_get_or_reserve_propagates_predicate_errors_without_reserving() {
        let mut table = HashConsTable::<u8, &str>::new();

        let slot = table.reserve_slot(7).expect("slot reserves");
        assert!(table.push_reserved(slot, "value"));

        let result = table.try_get_or_reserve(7, |_| {
            Err::<bool, AdmissionTestError>(AdmissionTestError::Predicate("boom"))
        });

        match result {
            Err(AdmissionTestError::Predicate("boom")) => {}
            other => panic!("expected predicate error, got {other:?}"),
        }
        assert_eq!(table.bucket_count(), 1);
        assert_eq!(table.bucket(&7), Some(["value"].as_slice()));
    }

    #[test]
    fn multiple_outstanding_slots_for_same_key_remain_reserved() {
        let mut table = HashConsTable::<u8, &str>::new();

        let first_slot = table.reserve_slot(7).expect("first slot reserves");
        let second_slot = table.reserve_slot(7).expect("second slot reserves");

        assert!(table.push_reserved(first_slot, "first"));
        assert!(table.push_reserved(second_slot, "second"));
        assert_eq!(table.bucket(&7), Some(["first", "second"].as_slice()));
    }

    #[test]
    fn cancel_reserved_releases_empty_bucket() {
        let mut table = HashConsTable::<u8, &str>::new();

        let slot = table.reserve_slot(7).expect("slot reserves");

        assert!(table.cancel_reserved(slot));
        assert!(table.is_empty());
    }

    #[test]
    fn cancel_reserved_keeps_existing_values() {
        let mut table = HashConsTable::<u8, &str>::new();

        let existing_slot = table.reserve_slot(7).expect("existing slot reserves");
        assert!(table.push_reserved(existing_slot, "existing"));
        let canceled_slot = table.reserve_slot(7).expect("canceled slot reserves");

        assert!(table.cancel_reserved(canceled_slot));
        assert_eq!(table.bucket(&7), Some(["existing"].as_slice()));
    }

    #[test]
    fn clone_drops_outstanding_reservations() {
        let mut table = HashConsTable::<u8, &str>::new();

        let existing_slot = table.reserve_slot(7).expect("existing slot reserves");
        assert!(table.push_reserved(existing_slot, "existing"));
        let outstanding_existing_key = table.reserve_slot(7).expect("existing key reserves");
        let reservation_only_key = table.reserve_slot(9).expect("empty key reserves");

        let mut cloned = table.clone();

        assert_eq!(cloned.bucket(&7), Some(["existing"].as_slice()));
        assert_eq!(cloned.bucket(&9), None);
        assert!(!cloned.push_reserved(outstanding_existing_key, "wrong"));
        assert!(!cloned.cancel_reserved(reservation_only_key));
        let cloned_slot = cloned.reserve_slot(7).expect("clone reserves its own slot");
        assert!(cloned.push_reserved(cloned_slot, "clone"));
        assert_eq!(cloned.bucket(&7), Some(["existing", "clone"].as_slice()));
    }

    #[test]
    fn try_rekey_committed_rebuilds_values_without_outstanding_reservations() {
        let mut table = HashConsTable::<u8, &str>::new();
        let short = table.reserve_slot(1).expect("short slot reserves");
        assert!(table.push_reserved(short, "a"));
        let long = table.reserve_slot(2).expect("long slot reserves");
        assert!(table.push_reserved(long, "three"));
        let outstanding = table.reserve_slot(9).expect("outstanding slot reserves");

        let rebuilt = table
            .try_rekey_committed::<HashConsError>(|value| Ok(value.len() as u8))
            .expect("committed values rekey");

        assert_eq!(rebuilt.bucket(&1), Some(["a"].as_slice()));
        assert_eq!(rebuilt.bucket(&5), Some(["three"].as_slice()));
        assert_eq!(rebuilt.bucket(&9), None);
        assert_eq!(table.bucket(&1), Some(["a"].as_slice()));
        assert!(table.cancel_reserved(outstanding));
    }
}
