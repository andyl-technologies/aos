//! Fallibly allocated canonical set storage.

use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{BoundedCborError, BoundedVec, collection_resource};

/// A canonically ordered set backed by one fallibly grown vector.
pub(crate) struct BoundedSet<T, const MAX: u64> {
    values: Vec<T>,
}

impl<T: Ord, const MAX: u64> BoundedSet<T, MAX> {
    /// Creates an empty canonical set.
    pub(crate) const fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// Returns the number of retained values.
    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }

    /// Iterates values in canonical order.
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &T> {
        self.values.iter()
    }

    /// Inserts one value after fallibly admitting vector growth.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedCborError::ResourceLimit`] when a new value would
    /// exceed the compiled entry ceiling or its storage cannot be reserved.
    pub(crate) fn try_insert(&mut self, value: T) -> Result<bool, BoundedCborError> {
        match self.values.binary_search(&value) {
            Ok(_index) => Ok(false),
            Err(index) => {
                let current = u64::try_from(self.values.len()).unwrap_or(u64::MAX);
                if current >= MAX {
                    return Err(collection_resource("bounded CBOR set", current, 1, MAX));
                }
                self.values
                    .try_reserve(1)
                    .map_err(|_| collection_resource("bounded CBOR set", current, 1, MAX))?;
                self.values.insert(index, value);
                Ok(true)
            }
        }
    }

    /// Retains values selected by `keep` without allocating.
    pub(crate) fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.values.retain(keep);
    }
}

impl<T: Clone, const MAX: u64> BoundedSet<T, MAX> {
    /// Fallibly clones the ordered value vector.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedCborError::ResourceLimit`] if the destination cannot be
    /// reserved.
    pub(crate) fn try_clone(&self) -> Result<Self, BoundedCborError> {
        let mut values = Vec::new();
        values.try_reserve_exact(self.values.len()).map_err(|_| {
            collection_resource(
                "bounded CBOR set",
                0,
                u64::try_from(self.values.len()).unwrap_or(u64::MAX),
                MAX,
            )
        })?;
        values.extend(self.values.iter().cloned());
        Ok(Self { values })
    }
}

impl<T: Ord, const MAX: u64> Default for BoundedSet<T, MAX> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: std::fmt::Debug, const MAX: u64> std::fmt::Debug for BoundedSet<T, MAX> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_set().entries(&self.values).finish()
    }
}

impl<T: PartialEq, const MAX: u64> PartialEq for BoundedSet<T, MAX> {
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values
    }
}

impl<T: Eq, const MAX: u64> Eq for BoundedSet<T, MAX> {}

impl<'a, T, const MAX: u64> IntoIterator for &'a BoundedSet<T, MAX> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

impl<T: Serialize, const MAX: u64> Serialize for BoundedSet<T, MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.values.len()))?;
        for value in &self.values {
            sequence.serialize_element(value)?;
        }
        sequence.end()
    }
}

impl<'de, T: Deserialize<'de> + Ord, const MAX: u64> Deserialize<'de> for BoundedSet<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let values = BoundedVec::<T, MAX>::deserialize(deserializer)?.into_inner();
        if values.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(serde::de::Error::custom(
                "bounded CBOR set values are not strictly ordered",
            ));
        }
        Ok(Self { values })
    }
}
