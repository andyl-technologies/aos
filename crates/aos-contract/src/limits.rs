//! Bounded decoding for untrusted JSON contract documents.

use anyhow::{Result, bail};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::canonical;

/// Closed resource limits applied before a JSON contract is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonLimits {
    /// Maximum encoded document size in bytes.
    pub max_bytes: usize,
    /// Maximum nesting depth, counting the root value as depth one.
    pub max_depth: usize,
    /// Maximum total number of array elements and object members.
    pub max_items: usize,
    /// Maximum UTF-8 byte length of a string value or object member name.
    pub max_string_bytes: usize,
}

impl JsonLimits {
    /// Validates and decodes one strict JSON document.
    ///
    /// # Errors
    ///
    /// Returns an error when an encoded or structural limit is exceeded, the
    /// JSON is ambiguous, or the value does not satisfy `T`'s schema.
    pub fn decode<T>(&self, bytes: &[u8], label: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        if bytes.len() > self.max_bytes {
            bail!("{label} exceeds the {} byte limit", self.max_bytes);
        }

        let value = canonical::parse_json(bytes, label)?;
        let mut items = 0_usize;
        validate_value(&value, self, 1, &mut items, label)?;
        serde_json::from_value(value)
            .map_err(|error| anyhow::anyhow!("invalid {label} schema: {error}"))
    }
}

fn validate_value(
    value: &Value,
    limits: &JsonLimits,
    depth: usize,
    items: &mut usize,
    label: &str,
) -> Result<()> {
    if depth > limits.max_depth {
        bail!(
            "{label} exceeds the nesting depth limit of {}",
            limits.max_depth
        );
    }

    match value {
        Value::String(text) => validate_string(text, limits, label),
        Value::Array(values) => {
            add_items(items, values.len(), limits, label)?;
            for child in values {
                validate_value(child, limits, depth + 1, items, label)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            add_items(items, object.len(), limits, label)?;
            for (name, child) in object {
                validate_string(name, limits, label)?;
                validate_value(child, limits, depth + 1, items, label)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn validate_string(text: &str, limits: &JsonLimits, label: &str) -> Result<()> {
    if text.len() > limits.max_string_bytes {
        bail!(
            "{label} contains a string exceeding the {} byte limit",
            limits.max_string_bytes
        );
    }
    Ok(())
}

fn add_items(items: &mut usize, additional: usize, limits: &JsonLimits, label: &str) -> Result<()> {
    *items = items
        .checked_add(additional)
        .ok_or_else(|| anyhow::anyhow!("{label} item count overflow"))?;
    if *items > limits.max_items {
        bail!("{label} exceeds the item limit of {}", limits.max_items);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    const LIMITS: JsonLimits = JsonLimits {
        max_bytes: 64,
        max_depth: 3,
        max_items: 3,
        max_string_bytes: 8,
    };

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        value: String,
    }

    #[test]
    fn accepts_values_inside_every_limit() -> Result<()> {
        let decoded: Fixture = LIMITS.decode(br#"{"value":"current"}"#, "fixture")?;
        assert_eq!(
            decoded,
            Fixture {
                value: "current".to_string()
            }
        );
        Ok(())
    }

    #[test]
    fn rejects_each_resource_boundary() {
        assert!(LIMITS.decode::<Value>(&[b' '; 65], "fixture").is_err());
        assert!(LIMITS.decode::<Value>(br#"[[[[]]]]"#, "fixture").is_err());
        assert!(LIMITS.decode::<Value>(br#"[1,2,3,4]"#, "fixture").is_err());
        assert!(
            LIMITS
                .decode::<Value>(br#""123456789""#, "fixture")
                .is_err()
        );
    }

    #[test]
    fn retains_strict_and_closed_schema_behavior() {
        assert!(
            LIMITS
                .decode::<Value>(br#"{"a":1,"a":2}"#, "fixture")
                .is_err()
        );
        assert!(
            LIMITS
                .decode::<Fixture>(br#"{"value":"ok","extra":1}"#, "fixture")
                .is_err()
        );
    }
}
