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

use thiserror::Error;

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
#[derive(Clone, Debug)]
pub struct HashConsTable<K, V> {
    buckets: HashMap<K, Vec<V>>,
}

/// Reserves one candidate slot in a [`HashConsTable`].
#[derive(Debug)]
pub struct HashConsSlot<K> {
    key: K,
}

impl<K, V> HashConsTable<K, V> {
    /// Creates an empty hash-cons table.
    pub fn new() -> Self {
        Self {
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
        self.buckets.get(key).map(Vec::as_slice)
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
        for candidate in bucket {
            if matches(candidate)? {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    /// Reserves one additional candidate slot for `key`.
    ///
    /// Callers use this before allocating the value that will be pushed into
    /// the bucket. The returned slot token is consumed by
    /// [`HashConsTable::push_reserved`], so public callers cannot push without
    /// first reserving.
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
            let entries = bucket
                .len()
                .checked_add(1)
                .ok_or(HashConsError::BucketLengthOverflow)?;
            bucket
                .try_reserve_exact(1)
                .map_err(|_| HashConsError::BucketAllocationFailed { entries })?;
            return Ok(HashConsSlot { key });
        }

        self.buckets
            .try_reserve(1)
            .map_err(|_| HashConsError::TableAllocationFailed {
                entries: self.buckets.len().saturating_add(1),
            })?;
        let mut bucket = Vec::new();
        bucket
            .try_reserve_exact(1)
            .map_err(|_| HashConsError::BucketAllocationFailed { entries: 1 })?;
        self.buckets.insert(key.clone(), bucket);
        Ok(HashConsSlot { key })
    }

    /// Pushes a value into a reserved bucket.
    ///
    /// Returns `false` when no bucket exists for the slot key, which indicates
    /// the slot came from a different table or the table was otherwise changed
    /// between reservation and push.
    pub fn push_reserved(&mut self, slot: HashConsSlot<K>, value: V) -> bool {
        let Some(bucket) = self.buckets.get_mut(&slot.key) else {
            return false;
        };
        bucket.push(value);
        true
    }
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
}
