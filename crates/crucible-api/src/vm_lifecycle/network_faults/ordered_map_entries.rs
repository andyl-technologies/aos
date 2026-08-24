//! Canonical sequence encoding for checkpoint maps whose keys are not JSON strings.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Serializes entries in their strict `BTreeMap` key order.
///
/// # Errors
///
/// Returns the serializer's error when an entry cannot be encoded.
pub(super) fn serialize<S, K, V>(value: &BTreeMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    K: Serialize,
    V: Serialize,
{
    value.iter().collect::<Vec<_>>().serialize(serializer)
}

/// Decodes entries while rejecting duplicates and noncanonical order.
///
/// # Errors
///
/// Returns a deserialization error for malformed, duplicate, or unordered entries.
pub(super) fn deserialize<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    let entries = Vec::<(K, V)>::deserialize(deserializer)?;
    let mut result = BTreeMap::new();
    for (key, value) in entries {
        if result
            .last_key_value()
            .is_some_and(|(prior, _value)| prior >= &key)
        {
            return Err(serde::de::Error::custom(
                "checkpoint map entries are not in strict canonical order",
            ));
        }
        result.insert(key, value);
    }
    Ok(result)
}
