//! Bounded canonical literals used by module option values.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

use crate::limits::ABILITY_LIMITS_V1;

/// Reports why a value cannot enter a canonical ability contract.
#[derive(Debug, Error)]
pub enum ValueError {
    /// The value exceeded a version-1 structural or size bound.
    #[error("value exceeds the version-1 {limit} limit")]
    Limit {
        /// Names the exceeded limit.
        limit: &'static str,
    },
    /// The value violated the canonical JSON dialect.
    #[error("value is outside the AOS canonical JSON dialect")]
    Canonical {
        /// Retains the canonical encoder's error chain.
        #[source]
        source: anyhow::Error,
    },
}

impl ValueError {
    /// Returns the stable diagnostic code for this canonical-value failure.
    #[must_use]
    pub const fn diagnostic_code(&self) -> crate::DiagnosticCode {
        match self {
            Self::Limit { .. } => crate::DiagnosticCode::LimitExceeded,
            Self::Canonical { .. } => crate::DiagnosticCode::ValueTypeMismatch,
        }
    }
}

/// Holds one value already checked against the canonical JSON dialect.
///
/// Schema validation remains a separate operation because the expected schema
/// belongs to an interface method or result port, not to the value itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbilityValue(Value);

impl AbilityValue {
    /// Constructs a value after checking canonical-dialect restrictions.
    ///
    /// # Errors
    ///
    /// Returns an error for floating-point or out-of-range numbers and for
    /// non-ASCII object member names. It also rejects values exceeding the
    /// version-1 depth, collection, string, or encoded-byte bounds.
    pub fn new(value: Value) -> Result<Self, ValueError> {
        let encoded_size = validate_value_limits(&value, &ABILITY_LIMITS_V1)?;
        if encoded_size > ABILITY_LIMITS_V1.max_document_bytes {
            return Err(ValueError::Limit {
                limit: "encoded byte",
            });
        }

        let bytes = aos_core::json::canonical_json(&value)
            .map_err(|source| ValueError::Canonical { source })?;
        debug_assert_eq!(bytes.len() as u64, encoded_size);
        Ok(Self(value))
    }

    /// Returns the underlying JSON value for schema-directed inspection.
    #[must_use]
    pub fn as_json(&self) -> &Value {
        &self.0
    }

    /// Returns the exact canonical encoded size after rechecking value bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if an in-memory value exceeds the version-1 structural,
    /// collection, string, or encoded-byte limits.
    pub fn encoded_size(&self) -> Result<u64, ValueError> {
        validate_value_limits(&self.0, &ABILITY_LIMITS_V1)
    }

    /// Consumes the wrapper and returns the underlying JSON value.
    #[must_use]
    pub fn into_json(self) -> Value {
        self.0
    }
}

impl TryFrom<Value> for AbilityValue {
    type Error = ValueError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for AbilityValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AbilityValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

fn validate_value_limits(
    root: &Value,
    limits: &crate::limits::LimitProfile,
) -> Result<u64, ValueError> {
    let mut item_count = 0_u64;
    let mut encoded_size = 0_u64;
    let mut stack = vec![(root, 1_u32)];

    while let Some((value, depth)) = stack.pop() {
        if depth > limits.max_structural_depth {
            return Err(ValueError::Limit { limit: "depth" });
        }

        match value {
            Value::Null => add_encoded_size(&mut encoded_size, 4, limits)?,
            Value::Bool(true) => add_encoded_size(&mut encoded_size, 4, limits)?,
            Value::Bool(false) => add_encoded_size(&mut encoded_size, 5, limits)?,
            Value::Number(number) => {
                add_encoded_size(&mut encoded_size, number.to_string().len() as u64, limits)?;
            }
            Value::String(text) => {
                validate_string_length(text, limits)?;
                add_encoded_size(&mut encoded_size, encoded_string_size(text), limits)?;
            }
            Value::Array(values) => {
                add_collection_items(&mut item_count, values.len() as u64, limits)?;
                add_encoded_size(
                    &mut encoded_size,
                    collection_punctuation(values.len()),
                    limits,
                )?;
                for child in values {
                    stack.push((child, depth.saturating_add(1)));
                }
            }
            Value::Object(object) => {
                add_collection_items(&mut item_count, object.len() as u64, limits)?;
                add_encoded_size(
                    &mut encoded_size,
                    collection_punctuation(object.len()),
                    limits,
                )?;
                for (name, child) in object {
                    validate_string_length(name, limits)?;
                    add_encoded_size(
                        &mut encoded_size,
                        encoded_string_size(name).saturating_add(1),
                        limits,
                    )?;
                    stack.push((child, depth.saturating_add(1)));
                }
            }
        }
    }

    Ok(encoded_size)
}

fn add_collection_items(
    item_count: &mut u64,
    additional: u64,
    limits: &crate::limits::LimitProfile,
) -> Result<(), ValueError> {
    *item_count = item_count
        .checked_add(additional)
        .ok_or(ValueError::Limit {
            limit: "collection item",
        })?;
    if *item_count > limits.max_collection_items {
        return Err(ValueError::Limit {
            limit: "collection item",
        });
    }
    Ok(())
}

fn add_encoded_size(
    encoded_size: &mut u64,
    additional: u64,
    limits: &crate::limits::LimitProfile,
) -> Result<(), ValueError> {
    *encoded_size = encoded_size
        .checked_add(additional)
        .ok_or(ValueError::Limit {
            limit: "encoded byte",
        })?;
    if *encoded_size > limits.max_document_bytes {
        return Err(ValueError::Limit {
            limit: "encoded byte",
        });
    }
    Ok(())
}

fn collection_punctuation(length: usize) -> u64 {
    if length == 0 {
        2
    } else {
        (length as u64).saturating_add(1)
    }
}

fn encoded_string_size(value: &str) -> u64 {
    let contents = value.chars().fold(0_u64, |size, character| {
        let escaped = match character {
            '\u{0008}' | '\t' | '\n' | '\u{000c}' | '\r' | '"' | '\\' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8() as u64,
        };
        size.saturating_add(escaped)
    });
    contents.saturating_add(2)
}

fn validate_string_length(
    value: &str,
    limits: &crate::limits::LimitProfile,
) -> Result<(), ValueError> {
    if value.len() as u64 > limits.max_string_bytes {
        return Err(ValueError::Limit {
            limit: "string byte",
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn value_limits_reject_collection_growth_before_traversal() {
        let limits = crate::limits::LimitProfile {
            max_collection_items: 2,
            ..ABILITY_LIMITS_V1
        };
        let value = Value::Array(vec![Value::Null, Value::Null, Value::Null]);

        assert!(matches!(
            validate_value_limits(&value, &limits),
            Err(ValueError::Limit {
                limit: "collection item"
            })
        ));
    }

    #[test]
    fn value_limits_precompute_encoded_size() {
        let limits = crate::limits::LimitProfile {
            max_document_bytes: 5,
            ..ABILITY_LIMITS_V1
        };
        let value = Value::String("1234".to_string());

        assert!(matches!(
            validate_value_limits(&value, &limits),
            Err(ValueError::Limit {
                limit: "encoded byte"
            })
        ));
    }
}
