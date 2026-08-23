//! Fallibly allocated canonical map storage.

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{BoundedCborError, collection_resource, resource_message};

/// A canonically ordered map backed by one fallibly grown vector.
pub(crate) struct BoundedMap<K, V, const MAX: u64> {
    entries: Vec<(K, V)>,
}

impl<K: Ord, V, const MAX: u64> BoundedMap<K, V, MAX> {
    /// Creates an empty canonical map.
    pub(crate) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Returns the number of retained entries.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Iterates entries in canonical key order.
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = (&K, &V)> {
        self.entries.iter().map(|(key, value)| (key, value))
    }

    /// Borrows the canonical entry storage.
    pub(crate) fn as_slice(&self) -> &[(K, V)] {
        &self.entries
    }

    /// Iterates keys in canonical order.
    pub(crate) fn keys(&self) -> impl ExactSizeIterator<Item = &K> {
        self.entries.iter().map(|(key, _value)| key)
    }

    /// Iterates values in canonical key order.
    pub(crate) fn values(&self) -> impl ExactSizeIterator<Item = &V> {
        self.entries.iter().map(|(_key, value)| value)
    }

    /// Finds one value by canonical key.
    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.entries
            .binary_search_by(|(candidate, _value)| candidate.cmp(key))
            .ok()
            .map(|index| &self.entries[index].1)
    }

    /// Finds one mutable value by canonical key.
    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries
            .binary_search_by(|(candidate, _value)| candidate.cmp(key))
            .ok()
            .map(|index| &mut self.entries[index].1)
    }

    /// Reserves storage for later inserts without changing canonical contents.
    pub(crate) fn try_reserve(&mut self, additional: usize) -> Result<(), BoundedCborError> {
        let current = u64::try_from(self.entries.len()).unwrap_or(u64::MAX);
        let requested = u64::try_from(additional).unwrap_or(u64::MAX);
        if current.saturating_add(requested) > MAX {
            return Err(collection_resource(
                "bounded CBOR map",
                current,
                requested,
                MAX,
            ));
        }
        self.entries
            .try_reserve(additional)
            .map_err(|_| collection_resource("bounded CBOR map", current, requested, MAX))
    }

    /// Returns the admitted entry capacity for precommit staging tests.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    /// Inserts or replaces one entry after fallibly admitting vector growth.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedCborError::ResourceLimit`] if a new entry would exceed
    /// the compiled entry ceiling or its storage cannot be reserved.
    pub(crate) fn try_insert(&mut self, key: K, value: V) -> Result<Option<V>, BoundedCborError> {
        match self
            .entries
            .binary_search_by(|(candidate, _value)| candidate.cmp(&key))
        {
            Ok(index) => Ok(Some(std::mem::replace(&mut self.entries[index].1, value))),
            Err(index) => {
                let current = u64::try_from(self.entries.len()).unwrap_or(u64::MAX);
                if current >= MAX {
                    return Err(collection_resource("bounded CBOR map", current, 1, MAX));
                }
                self.entries
                    .try_reserve(1)
                    .map_err(|_| collection_resource("bounded CBOR map", current, 1, MAX))?;
                self.entries.insert(index, (key, value));
                Ok(None)
            }
        }
    }

    /// Removes every entry without releasing the admitted allocation.
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}

impl<K, V, const MAX: u64> BoundedMap<K, V, MAX> {
    /// Fallibly duplicates the ordered map and each heap-owning entry.
    ///
    /// # Errors
    ///
    /// Returns the caller's allocation error if the destination entry vector
    /// or any key or value cannot be duplicated.
    pub(crate) fn try_clone_with<E>(
        &self,
        mut clone_key: impl FnMut(&K) -> Result<K, E>,
        mut clone_value: impl FnMut(&V) -> Result<V, E>,
        allocation_error: impl FnOnce() -> E,
    ) -> Result<Self, E> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.entries.len())
            .map_err(|_| allocation_error())?;
        for (key, value) in &self.entries {
            entries.push((clone_key(key)?, clone_value(value)?));
        }
        Ok(Self { entries })
    }
}

impl<K: std::fmt::Debug + Ord, V: std::fmt::Debug, const MAX: u64> std::fmt::Debug
    for BoundedMap<K, V, MAX>
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_map().entries(self.iter()).finish()
    }
}

impl<K: Ord, V, const MAX: u64> Default for BoundedMap<K, V, MAX> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: PartialEq, V: PartialEq, const MAX: u64> PartialEq for BoundedMap<K, V, MAX> {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl<K: Eq, V: Eq, const MAX: u64> Eq for BoundedMap<K, V, MAX> {}

impl<'a, K, V, const MAX: u64> IntoIterator for &'a BoundedMap<K, V, MAX> {
    type Item = (&'a K, &'a V);
    type IntoIter = std::iter::Map<std::slice::Iter<'a, (K, V)>, fn(&(K, V)) -> (&K, &V)>;

    fn into_iter(self) -> Self::IntoIter {
        fn borrow_entry<K, V>((key, value): &(K, V)) -> (&K, &V) {
            (key, value)
        }
        self.entries.iter().map(borrow_entry::<K, V>)
    }
}

impl<K, V, const MAX: u64> IntoIterator for BoundedMap<K, V, MAX> {
    type Item = (K, V);
    type IntoIter = std::vec::IntoIter<(K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<K: Serialize, V: Serialize, const MAX: u64> Serialize for BoundedMap<K, V, MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.entries.len()))?;
        for (key, value) in &self.entries {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>, const MAX: u64> Deserialize<'de>
    for BoundedMap<K, V, MAX>
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedMapVisitor<K, V, const MAX: u64>(std::marker::PhantomData<(K, V)>);

        impl<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>, const MAX: u64> Visitor<'de>
            for BoundedMapVisitor<K, V, MAX>
        {
            type Value = BoundedMap<K, V, MAX>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "at most {MAX} strictly ordered map entries")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let hint = map.size_hint().unwrap_or(0);
                let requested = u64::try_from(hint).unwrap_or(u64::MAX);
                if requested > MAX {
                    return Err(serde::de::Error::custom(resource_message(
                        "bounded CBOR map",
                        0,
                        requested,
                        MAX,
                        MAX,
                    )));
                }
                let mut entries: Vec<(K, V)> = Vec::new();
                let initial = hint.min(1024);
                entries.try_reserve_exact(initial).map_err(|_| {
                    serde::de::Error::custom(resource_message(
                        "bounded CBOR map",
                        0,
                        initial as u64,
                        MAX,
                        MAX,
                    ))
                })?;
                loop {
                    let current = u64::try_from(entries.len()).unwrap_or(u64::MAX);
                    if current >= MAX {
                        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom(resource_message(
                                "bounded CBOR map",
                                current,
                                1,
                                MAX,
                                MAX,
                            )));
                        }
                        break;
                    }
                    if entries.len() == entries.capacity() {
                        entries.try_reserve(1).map_err(|_| {
                            serde::de::Error::custom(resource_message(
                                "bounded CBOR map",
                                current,
                                1,
                                MAX,
                                MAX,
                            ))
                        })?;
                    }
                    let Some((key, value)) = map.next_entry()? else {
                        break;
                    };
                    if entries.last().is_some_and(|(prior, _value)| prior >= &key) {
                        return Err(serde::de::Error::custom(
                            "bounded CBOR map keys are not strictly ordered",
                        ));
                    }
                    entries.push((key, value));
                }
                Ok(BoundedMap { entries })
            }
        }

        deserializer.deserialize_map(BoundedMapVisitor::<K, V, MAX>(std::marker::PhantomData))
    }
}
