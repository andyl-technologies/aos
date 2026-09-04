//! Ordered and bounded OCI annotation maps.
//!
//! Unknown keys are intentionally preserved. RFC-0018 bounds UTF-8 bytes rather
//! than character counts: one key may occupy 1 KiB, one value 4 KiB, and the sum
//! of all key and value bytes on an object may occupy 64 KiB.
//!
//! ```text
//! {
//!   "com.example.extension": "retained verbatim",
//!   "org.opencontainers.image.version": "1.0.0"
//! }
//! ```

use std::collections::BTreeMap;

use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};
use crate::limits::{MAX_ANNOTATION_KEY_BYTES, MAX_ANNOTATION_VALUE_BYTES, MAX_ANNOTATIONS_BYTES};

/// A lexicographically ordered OCI annotation map with frozen byte bounds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Annotations(BTreeMap<String, String>);

impl Annotations {
    /// Creates an empty annotation map.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Validates and constructs annotations from an ordered map.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or overlong key, an overlong value, or an
    /// aggregate key-plus-value size above 64 KiB.
    pub fn from_map(map: BTreeMap<String, String>) -> Result<Self> {
        validate_map(&map)?;
        Ok(Self(map))
    }

    /// Inserts one annotation while preserving all bounds.
    ///
    /// The map is unchanged when validation fails.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or overlong key, an overlong value, or an
    /// aggregate key-plus-value size above 64 KiB.
    pub fn insert(&mut self, key: String, value: String) -> Result<Option<String>> {
        let mut candidate = self.0.clone();
        let previous = candidate.insert(key, value);
        validate_map(&candidate)?;
        self.0 = candidate;
        Ok(previous)
    }

    /// Validates the current annotation map.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or overlong key, an overlong value, or an
    /// aggregate key-plus-value size above 64 KiB.
    pub fn validate(&self) -> Result<()> {
        validate_map(&self.0)
    }

    /// Returns a value by its exact annotation key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Returns the number of annotations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the map contains no annotations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates in canonical key order.
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, String, String> {
        self.0.iter()
    }

    /// Borrows the ordered map.
    #[must_use]
    pub const fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    /// Consumes the annotations and returns the ordered map.
    #[must_use]
    pub fn into_map(self) -> BTreeMap<String, String> {
        self.0
    }
}

impl TryFrom<BTreeMap<String, String>> for Annotations {
    type Error = Error;

    fn try_from(map: BTreeMap<String, String>) -> Result<Self> {
        Self::from_map(map)
    }
}

impl Serialize for Annotations {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Annotations {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(AnnotationsVisitor)
    }
}

struct AnnotationsVisitor;

impl<'de> Visitor<'de> for AnnotationsVisitor {
    type Value = Annotations;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded string-to-string OCI annotation map")
    }

    fn visit_map<M>(self, mut input: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = BTreeMap::new();
        while let Some((key, value)) = input.next_entry::<String, String>()? {
            if map.insert(key.clone(), value).is_some() {
                return Err(serde::de::Error::custom(Error::DuplicateAnnotation { key }));
            }
        }
        Annotations::from_map(map).map_err(serde::de::Error::custom)
    }
}

fn validate_map(map: &BTreeMap<String, String>) -> Result<()> {
    let mut total = 0_usize;
    for (key, value) in map {
        if key.is_empty() {
            return Err(Error::InvalidAnnotations {
                reason: "annotation keys must not be empty".to_string(),
            });
        }
        if key.len() > MAX_ANNOTATION_KEY_BYTES {
            return Err(Error::InvalidAnnotations {
                reason: format!(
                    "key is {} bytes; the limit is {MAX_ANNOTATION_KEY_BYTES}",
                    key.len()
                ),
            });
        }
        if value.len() > MAX_ANNOTATION_VALUE_BYTES {
            return Err(Error::InvalidAnnotations {
                reason: format!(
                    "value for '{key}' is {} bytes; the limit is {MAX_ANNOTATION_VALUE_BYTES}",
                    value.len()
                ),
            });
        }
        total = total
            .checked_add(key.len())
            .and_then(|size| size.checked_add(value.len()))
            .ok_or_else(|| Error::InvalidAnnotations {
                reason: "aggregate annotation size overflowed usize".to_string(),
            })?;
        if total > MAX_ANNOTATIONS_BYTES {
            return Err(Error::InvalidAnnotations {
                reason: format!(
                    "aggregate key and value bytes are {total}; the limit is {MAX_ANNOTATIONS_BYTES}"
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn preserves_unknown_annotations_in_key_order() {
        let input = r#"{"z.example.extension":"z","a.example.extension":"a"}"#;
        let annotations: Annotations = serde_json::from_str(input).expect("annotations");
        assert_eq!(annotations.get("z.example.extension"), Some("z"));
        assert_eq!(
            serde_json::to_string(&annotations).expect("serialize"),
            r#"{"a.example.extension":"a","z.example.extension":"z"}"#
        );
    }

    #[test]
    fn rejects_duplicate_keys_before_map_collapse() {
        let input = r#"{"com.example.key":"one","com.example.key":"two"}"#;
        assert!(serde_json::from_str::<Annotations>(input).is_err());
    }

    #[test]
    fn enforces_each_exact_byte_boundary() {
        let mut annotations = Annotations::new();
        annotations
            .insert("k".repeat(MAX_ANNOTATION_KEY_BYTES), "".to_string())
            .expect("maximum key");
        assert!(
            annotations
                .insert("x".repeat(MAX_ANNOTATION_KEY_BYTES + 1), "".to_string())
                .is_err()
        );

        let mut annotations = Annotations::new();
        annotations
            .insert("value".to_string(), "v".repeat(MAX_ANNOTATION_VALUE_BYTES))
            .expect("maximum value");
        assert!(
            annotations
                .insert(
                    "too-large".to_string(),
                    "v".repeat(MAX_ANNOTATION_VALUE_BYTES + 1),
                )
                .is_err()
        );
    }

    #[test]
    fn enforces_the_aggregate_boundary_without_mutating_on_failure() {
        let mut map = BTreeMap::new();
        for index in 0..15 {
            map.insert(
                format!("k{index:02}"),
                "v".repeat(MAX_ANNOTATION_VALUE_BYTES),
            );
        }
        map.insert(
            "k15".to_string(),
            "v".repeat(MAX_ANNOTATIONS_BYTES - (16 * 3) - (15 * MAX_ANNOTATION_VALUE_BYTES)),
        );
        let mut annotations = Annotations::from_map(map).expect("exact aggregate limit");
        let snapshot = annotations.clone();
        assert!(annotations.insert("x".to_string(), String::new()).is_err());
        assert_eq!(annotations, snapshot);
    }
}
