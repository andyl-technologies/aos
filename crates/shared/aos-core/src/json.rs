//! Strict JSON parsing and the AOS integer-only canonical JSON dialect.
//!
//! Signed AOS release documents reject duplicate object members, floating
//! point numbers, non-ASCII member names, and integers outside the exact
//! I-JSON range. Canonical objects are ordered by member-name bytes.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};
use serde::Serialize;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

/// Parses one strict JSON value without accepting duplicate members or floats.
///
/// # Errors
///
/// Returns an error when the input is invalid JSON, contains a duplicate
/// member, contains a floating-point value, or has trailing data.
pub fn parse_json(bytes: &[u8], label: &str) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue::deserialize(&mut deserializer)
        .with_context(|| format!("invalid {label} JSON"))?;
    deserializer
        .end()
        .with_context(|| format!("trailing data in {label} JSON"))?;
    Ok(value.0)
}

/// Parses one strict JSON document into a closed schema type.
///
/// # Errors
///
/// Returns an error under the conditions described by [`parse_json`], or when
/// the resulting value does not satisfy `T`'s schema.
pub fn from_slice<T>(bytes: &[u8], label: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let value = parse_json(bytes, label)?;
    serde_json::from_value(value).with_context(|| format!("invalid {label} schema"))
}

/// Produces exact canonical bytes for an AOS signed JSON value.
///
/// # Errors
///
/// Returns an error for non-I-JSON integers, floating-point values, non-ASCII
/// member names, or a value that cannot be serialized as JSON.
pub fn to_vec<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let value = serde_json::to_value(value).context("converting value to canonical JSON")?;
    canonical_json(&value)
}

/// Produces exact canonical bytes for an already parsed JSON value.
///
/// # Errors
///
/// Returns an error for non-I-JSON integers, floating-point values, or
/// non-ASCII object member names.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    reject_non_i_json_numbers(value, "")?;
    let mut output = Vec::new();
    write_canonical(value, &mut output)?;
    Ok(output)
}

/// Verifies that bytes are the canonical encoding of one strict JSON value.
///
/// # Errors
///
/// Returns an error when parsing or canonicalization fails or when the bytes
/// do not exactly equal their canonical representation.
pub fn require_canonical(bytes: &[u8], label: &str) -> Result<Value> {
    let value = parse_json(bytes, label)?;
    if canonical_json(&value)? != bytes {
        bail!("{label} is not canonical JSON");
    }
    Ok(value)
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                output.extend_from_slice(integer.to_string().as_bytes());
            } else if let Some(integer) = number.as_u64() {
                output.extend_from_slice(integer.to_string().as_bytes());
            } else {
                bail!("AOS canonical JSON rejects non-integer numbers");
            }
        }
        Value::String(text) => output.extend_from_slice(serde_json::to_string(text)?.as_bytes()),
        Value::Array(values) => {
            output.push(b'[');
            for (index, child) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(child, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            let mut members: Vec<_> = object.iter().collect();
            if members.iter().any(|(name, _)| !name.is_ascii()) {
                bail!("AOS canonical JSON requires ASCII object member names");
            }
            members.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            output.push(b'{');
            for (index, (name, child)) in members.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(serde_json::to_string(name)?.as_bytes());
                output.push(b':');
                write_canonical(child, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn reject_non_i_json_numbers(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Number(number) => {
            const MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_991;
            let exact = number
                .as_i64()
                .map(|integer| integer.unsigned_abs() <= MAX_EXACT_INTEGER)
                .or_else(|| number.as_u64().map(|integer| integer <= MAX_EXACT_INTEGER))
                .unwrap_or(false);
            if !exact {
                bail!("non-I-JSON number at {path}");
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_non_i_json_numbers(child, &format!("{path}/{index}"))?;
            }
        }
        Value::Object(object) => {
            for (name, child) in object {
                reject_non_i_json_numbers(child, &format!("{path}/{name}"))?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate members or floating-point values")
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(
            "AOS canonical JSON rejects floating-point numbers",
        ))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = serde_json::Map::new();
        while let Some((name, value)) = map.next_entry::<String, UniqueValue>()? {
            if object.insert(name.clone(), value.0).is_some() {
                return Err(de::Error::custom(format!("duplicate JSON member: {name}")));
            }
        }
        Ok(UniqueValue(Value::Object(object)))
    }
}

/// Rejects obvious repeated-character placeholder hashes recursively.
///
/// # Errors
///
/// Returns an error when a 64-digit hexadecimal string uses no more than two
/// distinct characters.
pub fn reject_placeholder_hashes(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                reject_placeholder_hashes(child, &format!("{path}/{name}"))?;
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_placeholder_hashes(child, &format!("{path}/{index}"))?;
            }
        }
        Value::String(text)
            if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            let unique: BTreeSet<_> = text.bytes().collect();
            if unique.len() <= 2 {
                bail!("placeholder-pattern hash rejected at {path}");
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[test]
    fn member_order_is_stable() -> Result<()> {
        let left = serde_json::json!({"b": 2, "a": 1});
        let right = serde_json::json!({"a": 1, "b": 2});
        assert_eq!(canonical_json(&left)?, canonical_json(&right)?);
        Ok(())
    }

    #[test]
    fn parser_rejects_ambiguous_json() {
        assert!(parse_json(br#"{"a":1,"a":2}"#, "duplicate").is_err());
        assert!(parse_json(br#"{"value":1.5}"#, "float").is_err());
        assert!(parse_json(br#"{} trailing"#, "trailing").is_err());
    }

    #[test]
    fn canonical_encoding_is_required_exactly() {
        assert!(require_canonical(br#"{"a":1,"b":2}"#, "canonical").is_ok());
        assert!(require_canonical(br#"{ "a": 1, "b": 2 }"#, "spaced").is_err());
    }
}
