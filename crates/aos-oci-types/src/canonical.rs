//! Deterministic compact JSON serialization for AOS-generated OCI objects.
//!
//! Object keys are sorted lexicographically at every depth, arrays retain their
//! semantic order, insignificant whitespace is omitted, and floating-point
//! numbers are rejected. Uploaded manifest bytes are never run through this
//! function because their exact original serialization is their content
//! identity.

use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::limits::MAX_JSON_BYTES;

/// Serializes a value as compact, recursively key-sorted JSON without floats.
///
/// # Errors
///
/// Returns an error when Serde cannot represent `value`, when a floating-point
/// number appears anywhere in the value, or when the encoded document exceeds
/// [`MAX_JSON_BYTES`].
pub fn to_canonical_json<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let value = serde_json::to_value(value).map_err(|error| Error::Json {
        document: "canonical",
        message: error.to_string(),
    })?;
    let canonical = canonicalize(value)?;
    let encoded = serde_json::to_vec(&canonical).map_err(|error| Error::Json {
        document: "canonical",
        message: error.to_string(),
    })?;
    if encoded.len() > MAX_JSON_BYTES {
        return Err(Error::JsonTooLarge {
            document: "canonical",
            limit: MAX_JSON_BYTES,
            actual: encoded.len(),
        });
    }
    Ok(encoded)
}

pub(crate) fn parse_bounded<T>(bytes: &[u8], document: &'static str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    if bytes.len() > MAX_JSON_BYTES {
        return Err(Error::JsonTooLarge {
            document,
            limit: MAX_JSON_BYTES,
            actual: bytes.len(),
        });
    }
    serde_json::from_slice(bytes).map_err(|error| Error::Json {
        document,
        message: error.to_string(),
    })
}

fn canonicalize(value: Value) -> Result<Value> {
    match value {
        Value::Array(values) => values
            .into_iter()
            .map(canonicalize)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Object(fields) => {
            let mut entries = fields.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = serde_json::Map::new();
            for (key, value) in entries {
                sorted.insert(key, canonicalize(value)?);
            }
            Ok(Value::Object(sorted))
        }
        Value::Number(number) if number.is_f64() => Err(Error::FloatingPointNotCanonical),
        scalar => Ok(scalar),
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_types, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use serde::Serialize;

    use super::*;

    #[derive(Serialize)]
    struct Fixture {
        z: u64,
        nested: HashMap<String, u64>,
        a: Vec<u64>,
    }

    #[test]
    fn sorts_every_object_and_preserves_array_order() {
        let fixture = Fixture {
            z: 3,
            nested: HashMap::from([("z".to_string(), 2), ("a".to_string(), 1)]),
            a: vec![2, 1],
        };
        assert_eq!(
            to_canonical_json(&fixture).expect("canonical JSON"),
            br#"{"a":[2,1],"nested":{"a":1,"z":2},"z":3}"#
        );
    }

    #[test]
    fn rejects_floating_point_at_any_depth() {
        let value = serde_json::json!({"nested": [1, 1.5]});
        assert_eq!(
            to_canonical_json(&value),
            Err(Error::FloatingPointNotCanonical)
        );
    }

    #[test]
    fn bounds_input_before_decoding() {
        let oversized = vec![b' '; MAX_JSON_BYTES + 1];
        let error =
            parse_bounded::<serde_json::Value>(&oversized, "fixture").expect_err("oversized JSON");
        assert!(matches!(error, Error::JsonTooLarge { .. }));
    }
}
