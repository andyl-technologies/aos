//! Measures ordered comparisons in transaction-local grouping and staging maps.
//!
//! Digest staging keys are exactly 32 bytes. The current alloc BTreeMap has at
//! most eleven keys per search node and at least two children per internal
//! node; a digest population cannot require more than 257 search nodes. Thus
//! a requested staging operation makes at most 2827 ordered comparisons.
//! The report measures actual comparisons, not this conservative maximum.
//! Grouping/edit maps contain only delta-derived coordinates/rows; their
//! logarithmic population term is bounded as described in update.rs. Ordered
//! iteration visits each row once and does not allocate a second row vector.

use alloc::{
    collections::{BTreeMap, btree_map},
    rc::Rc,
};
use core::{cell::Cell, cmp::Ordering};

use super::{Error, TemporaryWork};

#[derive(Default)]
struct Counter {
    work: Cell<TemporaryWork>,
    overflow: Cell<bool>,
}

impl Counter {
    fn charge(&self, comparison: bool) {
        let mut work = self.work.get();
        let counter = if comparison {
            &mut work.comparisons
        } else {
            &mut work.operations
        };
        match counter.checked_add(1) {
            Some(next) => *counter = next,
            None => self.overflow.set(true),
        }
        self.work.set(work);
    }
}

/// Wraps an ordered key with shared comparison accounting.
pub(super) struct Key<K> {
    value: K,
    counter: Rc<Counter>,
}

impl<K: Ord> Ord for Key<K> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.counter.charge(true);
        self.value.cmp(&other.value)
    }
}

impl<K: Ord> PartialOrd for Key<K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K: Ord> PartialEq for Key<K> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<K: Ord> Eq for Key<K> {}

/// Holds transaction-local ordered values with deferred counter-overflow checks.
pub(super) struct Ordered<K, V> {
    values: BTreeMap<Key<K>, V>,
    counter: Rc<Counter>,
}

impl<K, V> Default for Ordered<K, V> {
    fn default() -> Self {
        Self {
            values: BTreeMap::new(),
            counter: Rc::default(),
        }
    }
}

impl<K: Ord + Clone, V> Ordered<K, V> {
    /// Creates an empty map with zeroed shared accounting.
    pub(super) fn new() -> Self {
        Self::default()
    }

    fn key(&self, value: K) -> Key<K> {
        self.counter.charge(false);
        Key {
            value,
            counter: Rc::clone(&self.counter),
        }
    }

    /// Returns an entry handle while recording its lookup and comparisons.
    pub(super) fn entry(&mut self, key: K) -> btree_map::Entry<'_, Key<K>, V> {
        let key = self.key(key);
        self.values.entry(key)
    }

    /// Borrows a value while recording the lookup and comparisons.
    pub(super) fn get(&self, key: &K) -> Option<&V> {
        self.values.get(&self.key(key.clone()))
    }

    /// Tests key membership through an accounted lookup.
    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Inserts a value, returning any replaced value and accounting for the search.
    pub(super) fn insert(&mut self, key: K, value: V) -> Option<V> {
        let key = self.key(key);
        self.values.insert(key, value)
    }

    /// Removes and returns a value if present, accounting for the search.
    pub(super) fn remove(&mut self, key: &K) -> Option<V> {
        let key = self.key(key.clone());
        self.values.remove(&key)
    }

    /// Returns whether the map contains no values without charging a lookup.
    pub(super) fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Borrows keys in ascending order without charging searches or comparisons.
    pub(super) fn keys(&self) -> impl Iterator<Item = &K> {
        self.values.keys().map(|key| &key.value)
    }

    /// Returns accumulated accounting after checking deferred counter overflow.
    ///
    /// # Errors
    /// Returns `Error::Limit` if any operation or comparison charge overflowed.
    pub(super) fn work(&self) -> Result<TemporaryWork, Error> {
        if self.counter.overflow.get() {
            Err(Error::Limit)
        } else {
            Ok(self.counter.work.get())
        }
    }
}

impl<K, V> IntoIterator for Ordered<K, V> {
    type Item = (K, V);
    type IntoIter = core::iter::Map<btree_map::IntoIter<Key<K>, V>, fn((Key<K>, V)) -> (K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.values
            .into_iter()
            .map(|(key, value)| (key.value, value))
    }
}
