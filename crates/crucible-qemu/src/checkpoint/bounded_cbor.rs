//! Fallible, premeasured canonical-CBOR envelope encoding.
//!
//! Checkpoint owners can contain large but valid queues. Serializing directly
//! into a growing [`Vec`] would let allocator failure abort the host before the
//! post-encode size check ran. This module counts the exact representation,
//! admits it against the configured and compiled ceilings, reserves once with
//! a fallible operation, and then writes only into that reservation.

use std::io::{self, Write};

use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[path = "bounded_cbor/set.rs"]
mod set;
pub(crate) use set::BoundedSet;

/// RFC-0014's compiled hard ceiling for one fat checkpoint artifact.
pub(crate) const HARD_FAT_CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Failure to admit or serialize a bounded CBOR envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundedCborError {
    /// Serialization encountered a value that CBOR cannot represent.
    Malformed,
    /// The encoded form or its allocation exceeds an active resource ceiling.
    ResourceLimit {
        field: &'static str,
        current: u64,
        requested: u64,
        configured: u64,
        hard: u64,
    },
}

/// A sequence whose decoder reserves fallibly and never grows beyond `MAX` entries.
///
/// Canonical CBOR normally supplies an exact sequence length, but the visitor
/// also handles indefinite hostile inputs by reserving each growth step before
/// asking `Vec` to append. Allocation refusal is therefore a decode error, not
/// a process abort.
pub(crate) struct BoundedVec<T, const MAX: u64> {
    values: Vec<T>,
}

impl<T, const MAX: u64> BoundedVec<T, MAX> {
    /// Wraps an already admitted vector.
    pub(crate) fn new(values: Vec<T>) -> Result<Self, BoundedCborError> {
        let requested = u64::try_from(values.len())
            .map_err(|_| resource("bounded CBOR sequence", 0, u64::MAX, MAX))?;
        if requested > MAX {
            return Err(resource("bounded CBOR sequence", 0, requested, MAX));
        }
        Ok(Self { values })
    }

    /// Borrows the admitted values.
    pub(crate) fn as_slice(&self) -> &[T] {
        &self.values
    }

    /// Returns the admitted vector.
    pub(crate) fn into_inner(self) -> Vec<T> {
        self.values
    }
}

impl<T: Serialize, const MAX: u64> Serialize for BoundedVec<T, MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.values.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>, const MAX: u64> Deserialize<'de> for BoundedVec<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedVisitor<T, const MAX: u64>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const MAX: u64> Visitor<'de> for BoundedVisitor<T, MAX> {
            type Value = BoundedVec<T, MAX>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "at most {MAX} sequence entries")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let hint = sequence.size_hint().unwrap_or(0);
                let requested = u64::try_from(hint).unwrap_or(u64::MAX);
                if requested > MAX {
                    return Err(serde::de::Error::custom(resource_message(
                        "bounded CBOR sequence",
                        0,
                        requested,
                        MAX,
                        MAX,
                    )));
                }
                let mut values = Vec::new();
                let initial = hint.min(1024);
                values.try_reserve_exact(initial).map_err(|_| {
                    serde::de::Error::custom(resource_message(
                        "bounded CBOR sequence",
                        0,
                        initial as u64,
                        MAX,
                        MAX,
                    ))
                })?;
                loop {
                    let current = u64::try_from(values.len()).unwrap_or(u64::MAX);
                    if current >= MAX {
                        if sequence.next_element::<IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom(resource_message(
                                "bounded CBOR sequence",
                                current,
                                1,
                                MAX,
                                MAX,
                            )));
                        }
                        break;
                    }
                    let Some(value) = sequence.next_element()? else {
                        break;
                    };
                    if values.len() == values.capacity() {
                        values.try_reserve(1).map_err(|_| {
                            serde::de::Error::custom(resource_message(
                                "bounded CBOR sequence",
                                current,
                                1,
                                MAX,
                                MAX,
                            ))
                        })?;
                    }
                    values.push(value);
                }
                Ok(BoundedVec { values })
            }
        }

        deserializer.deserialize_seq(BoundedVisitor::<T, MAX>(std::marker::PhantomData))
    }
}

/// A canonically ordered map backed by one fallibly grown vector.
///
/// Unlike [`std::collections::BTreeMap`], every allocation is made through a
/// recoverable `Vec::try_reserve` operation. Keys remain strictly increasing,
/// so lookup and canonical serialization do not depend on host hash state.
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

    /// Inserts or replaces one entry after fallibly admitting vector growth.
    ///
    /// # Errors
    ///
    /// Returns [`std::collections::TryReserveError`] if a new entry cannot be
    /// reserved. Replacement does not allocate.
    pub(crate) fn try_insert(
        &mut self,
        key: K,
        value: V,
    ) -> Result<Option<V>, std::collections::TryReserveError> {
        match self
            .entries
            .binary_search_by(|(candidate, _value)| candidate.cmp(&key))
        {
            Ok(index) => Ok(Some(std::mem::replace(&mut self.entries[index].1, value))),
            Err(index) => {
                self.entries.try_reserve(1)?;
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

impl<K: Clone, V: Clone, const MAX: u64> BoundedMap<K, V, MAX> {
    /// Fallibly clones the ordered entry vector.
    ///
    /// # Errors
    ///
    /// Returns [`std::collections::TryReserveError`] if the destination entry
    /// vector cannot be reserved.
    pub(crate) fn try_clone(&self) -> Result<Self, std::collections::TryReserveError> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(self.entries.len())?;
        entries.extend(self.entries.iter().cloned());
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
                    let Some((key, value)) = map.next_entry()? else {
                        break;
                    };
                    if entries.last().is_some_and(|(prior, _value)| prior >= &key) {
                        return Err(serde::de::Error::custom(
                            "bounded CBOR map keys are not strictly ordered",
                        ));
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
                    entries.push((key, value));
                }
                Ok(BoundedMap { entries })
            }
        }

        deserializer.deserialize_map(BoundedMapVisitor::<K, V, MAX>(std::marker::PhantomData))
    }
}

/// Encodes `value` after `magic` without an unbounded intermediate buffer.
pub(crate) fn encode_prefixed<T: Serialize>(
    value: &T,
    magic: &[u8],
    field: &'static str,
    configured: u64,
) -> Result<Vec<u8>, BoundedCborError> {
    let configured = configured.min(HARD_FAT_CHECKPOINT_BYTES);
    let mut counter = CountingWriter::new(field, configured);
    if ciborium::ser::into_writer(value, &mut counter).is_err() {
        return Err(counter.failure.unwrap_or(BoundedCborError::Malformed));
    }
    let total = admit(
        field,
        u64::try_from(magic.len()).map_err(|_| resource(field, 0, u64::MAX, configured))?,
        counter.length,
        configured,
    )?;
    let total_usize = usize::try_from(total).map_err(|_| resource(field, 0, total, configured))?;

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total_usize)
        .map_err(|_| resource(field, 0, total, configured))?;
    bytes.extend_from_slice(magic);
    let mut writer = ReservedWriter::new(&mut bytes, field, total);
    if ciborium::ser::into_writer(value, &mut writer).is_err() {
        return Err(writer.failure.unwrap_or(BoundedCborError::Malformed));
    }
    if u64::try_from(bytes.len()).ok() != Some(total) {
        return Err(BoundedCborError::Malformed);
    }
    Ok(bytes)
}

/// Admits a complete encoded input before any nested decoding allocation.
pub(crate) fn admit_input(
    bytes: &[u8],
    field: &'static str,
    configured: u64,
) -> Result<(), BoundedCborError> {
    let configured = configured.min(HARD_FAT_CHECKPOINT_BYTES);
    let requested =
        u64::try_from(bytes.len()).map_err(|_| resource(field, 0, u64::MAX, configured))?;
    admit(field, 0, requested, configured).map(|_| ())
}

/// Preserves resource coordinates carried by bounded serde visitors.
pub(crate) fn map_decode_error<T>(error: ciborium::de::Error<T>) -> BoundedCborError {
    let ciborium::de::Error::Semantic(_, message) = error else {
        return BoundedCborError::Malformed;
    };
    parse_resource_message(&message).unwrap_or(BoundedCborError::Malformed)
}

fn admit(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
) -> Result<u64, BoundedCborError> {
    let total = current
        .checked_add(requested)
        .ok_or_else(|| resource(field, current, requested, configured))?;
    if total > configured {
        return Err(resource(field, current, requested, configured));
    }
    Ok(total)
}

fn resource(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
) -> BoundedCborError {
    BoundedCborError::ResourceLimit {
        field,
        current,
        requested,
        configured,
        hard: HARD_FAT_CHECKPOINT_BYTES,
    }
}

fn resource_message(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> String {
    format!("crucible-resource-limit|{field}|{current}|{requested}|{configured}|{hard}")
}

fn parse_resource_message(message: &str) -> Option<BoundedCborError> {
    let mut fields = message.split('|');
    if fields.next()? != "crucible-resource-limit" {
        return None;
    }
    let field = match fields.next()? {
        "bounded CBOR sequence" => "bounded CBOR sequence",
        "bounded CBOR map" => "bounded CBOR map",
        _ => return None,
    };
    let current = fields.next()?.parse().ok()?;
    let requested = fields.next()?.parse().ok()?;
    let configured = fields.next()?.parse().ok()?;
    let hard = fields.next()?.parse().ok()?;
    if fields.next().is_some() {
        return None;
    }
    Some(BoundedCborError::ResourceLimit {
        field,
        current,
        requested,
        configured,
        hard,
    })
}

struct CountingWriter {
    field: &'static str,
    configured: u64,
    length: u64,
    failure: Option<BoundedCborError>,
}

impl CountingWriter {
    const fn new(field: &'static str, configured: u64) -> Self {
        Self {
            field,
            configured,
            length: 0,
            failure: None,
        }
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(buffer.len()).map_err(|_| {
            self.failure = Some(resource(self.field, self.length, u64::MAX, self.configured));
            io::Error::other("CBOR length is not representable")
        })?;
        self.length =
            admit(self.field, self.length, requested, self.configured).map_err(|error| {
                self.failure = Some(error);
                io::Error::other("CBOR envelope exceeds its resource ceiling")
            })?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ReservedWriter<'a> {
    bytes: &'a mut Vec<u8>,
    field: &'static str,
    maximum: u64,
    failure: Option<BoundedCborError>,
}

impl<'a> ReservedWriter<'a> {
    fn new(bytes: &'a mut Vec<u8>, field: &'static str, maximum: u64) -> Self {
        Self {
            bytes,
            field,
            maximum,
            failure: None,
        }
    }
}

impl Write for ReservedWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let current = u64::try_from(self.bytes.len()).map_err(|_| {
            self.failure = Some(resource(self.field, u64::MAX, 0, self.maximum));
            io::Error::other("CBOR output length is not representable")
        })?;
        let requested = u64::try_from(buffer.len()).map_err(|_| {
            self.failure = Some(resource(self.field, current, u64::MAX, self.maximum));
            io::Error::other("CBOR write length is not representable")
        })?;
        admit(self.field, current, requested, self.maximum).map_err(|error| {
            self.failure = Some(error);
            io::Error::other("CBOR serializer exceeded its measured reservation")
        })?;
        if buffer.len() > self.bytes.capacity().saturating_sub(self.bytes.len()) {
            let error = resource(self.field, current, requested, self.maximum);
            self.failure = Some(error);
            return Err(io::Error::other("CBOR serializer exceeded its reservation"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "bounded_cbor/tests.rs"]
mod tests;
