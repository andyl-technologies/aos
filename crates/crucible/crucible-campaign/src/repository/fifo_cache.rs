//! Bounded first-in, first-out memo for repository validation results.
//!
//! Validation caches only avoid repeated reads: a miss re-derives the same
//! result from authenticated records. A fixed capacity therefore bounds memory
//! without affecting correctness, however long a campaign grows.

use std::collections::{BTreeMap, VecDeque};

/// Map that evicts its oldest insertion once it holds `capacity` entries.
///
/// Reinserting an existing key keeps its original value and position.
pub(super) struct FifoCache<K, V> {
    capacity: usize,
    entries: BTreeMap<K, V>,
    insertion_order: VecDeque<K>,
}

impl<K: Ord + Clone, V> FifoCache<K, V> {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: BTreeMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    pub(super) fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn insert(&mut self, key: K, value: V) {
        if self.capacity == 0 || self.entries.contains_key(&key) {
            return;
        }
        if self.entries.len() >= self.capacity
            && let Some(evicted) = self.insertion_order.pop_front()
        {
            self.entries.remove(&evicted);
        }
        self.entries.insert(key.clone(), value);
        self.insertion_order.push_back(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_cache_evicts_the_oldest_insertion_at_capacity() {
        let mut cache = FifoCache::new(2);

        cache.insert(1, "one");
        cache.insert(2, "two");
        cache.insert(1, "replacement");
        cache.insert(3, "three");

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), Some(&"two"));
        assert_eq!(cache.get(&3), Some(&"three"));
    }

    #[test]
    fn zero_capacity_fifo_cache_stores_nothing() {
        let mut cache = FifoCache::new(0);

        cache.insert(1, ());

        assert_eq!(cache.len(), 0);
        assert!(!cache.contains_key(&1));
    }
}
