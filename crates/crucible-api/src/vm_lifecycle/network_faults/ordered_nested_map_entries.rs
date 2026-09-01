//! Canonical sequence encoding for nested checkpoint maps.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Serializes both map levels as canonical ordered entry sequences.
///
/// # Errors
///
/// Returns the serializer's error when an entry cannot be encoded.
pub(super) fn serialize<S, K, K2, V>(
    value: &BTreeMap<K, BTreeMap<K2, V>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    K: Serialize,
    K2: Serialize,
    V: Serialize,
{
    value
        .iter()
        .map(|(key, entries)| (key, entries.iter().collect::<Vec<_>>()))
        .collect::<Vec<_>>()
        .serialize(serializer)
}

/// Decodes both map levels while rejecting duplicates and noncanonical order.
///
/// # Errors
///
/// Returns a deserialization error for malformed, duplicate, or unordered entries.
pub(super) fn deserialize<'de, D, K, K2, V>(
    deserializer: D,
) -> Result<BTreeMap<K, BTreeMap<K2, V>>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    K2: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    let entries = Vec::<(K, Vec<(K2, V)>)>::deserialize(deserializer)?;
    let mut result = BTreeMap::new();
    for (key, nested_entries) in entries {
        if result
            .last_key_value()
            .is_some_and(|(prior, _value)| prior >= &key)
        {
            return Err(serde::de::Error::custom(
                "checkpoint outer map entries are not in strict canonical order",
            ));
        }
        let mut nested = BTreeMap::new();
        for (nested_key, value) in nested_entries {
            if nested
                .last_key_value()
                .is_some_and(|(prior, _value)| prior >= &nested_key)
            {
                return Err(serde::de::Error::custom(
                    "checkpoint nested map entries are not in strict canonical order",
                ));
            }
            nested.insert(nested_key, value);
        }
        result.insert(key, nested);
    }
    Ok(result)
}
