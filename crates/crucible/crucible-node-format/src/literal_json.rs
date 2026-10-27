//! Decodes CNP JSON data without interpreting implementation-private keys.
//!
//! An object such as `{"$serde_json::private::RawValue":"[0]"}` remains that
//! object. Its string is never reparsed as another document. This keeps JSON
//! fields independent of dependency features and the enclosing parser's limits.
//! Framing, nesting, byte limits and schema validation remain caller duties.

use crate::Extensions;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{collections::BTreeMap, fmt, marker::PhantomData, mem::size_of};

/// Deserializes one JSON value while preserving literal object keys and strings.
///
/// This helper is used by CNP schema fields through `serde(deserialize_with)`.
/// It does not recognize Serde's private raw-value or number marker objects.
///
/// # Errors
/// Refuses malformed JSON values, duplicate object keys, nonfinite numbers or
/// unavailable array storage. The caller separately enforces framing limits.
pub fn deserialize_value<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<Value, D::Error> {
    deserializer.deserialize_any(ValueVisitor)
}

/// Deserializes an arbitrary JSON object without reinterpreting private keys.
///
/// # Errors
/// Refuses a nonobject value, duplicate keys or invalid nested JSON values.
pub fn deserialize_object<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<Map<String, Value>, D::Error> {
    deserializer.deserialize_map(ObjectVisitor::<Map<String, Value>>(PhantomData))
}

/// Deserializes extension values as literal JSON without negotiating their use.
///
/// # Errors
/// Refuses a nonobject value, duplicate keys or invalid nested JSON values.
pub fn deserialize_extensions<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<Extensions, D::Error> {
    deserializer.deserialize_map(ObjectVisitor::<Extensions>(PhantomData))
}

/// Deserializes an explicitly present JSON object or null with literal contents.
///
/// Unlike ordinary Option deserialization, the entry point requests a value;
/// a schema's missing-field deserializer cannot silently supply null.
///
/// # Errors
/// Refuses omission, a nonobject nonnull value, duplicate keys or invalid
/// nested JSON values.
pub fn deserialize_optional_object<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Map<String, Value>>, D::Error> {
    deserializer.deserialize_any(OptionalObjectVisitor)
}

/// Names the literal decoder's fixed visitor, field and result controls.
///
/// Dynamic output backing, recursive traversal and physical stack storage
/// require separate bounds. This counter grants no allocation or Source right.
pub const fn deserialization_counter_scratch_data() -> usize {
    size_of::<ValueVisitor>()
        + size_of::<ValueSeed>()
        + size_of::<ObjectVisitor<Map<String, Value>>>()
        + size_of::<ObjectVisitor<Extensions>>()
        + size_of::<OptionalObjectVisitor>()
        + size_of::<Value>()
        + size_of::<Number>()
        + size_of::<String>()
        + size_of::<Vec<Value>>()
        + size_of::<Map<String, Value>>()
        + size_of::<Extensions>()
        + size_of::<Option<String>>()
        + size_of::<Option<Value>>()
        + size_of::<Option<usize>>()
        + size_of::<Option<Map<String, Value>>>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<Result<Map<String, Value>, serde_json::Error>>()
        + size_of::<Result<Extensions, serde_json::Error>>()
        + size_of::<Result<Option<Map<String, Value>>, serde_json::Error>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<&str>()
        + size_of::<usize>()
}

struct ValueSeed;

impl<'de> DeserializeSeed<'de> for ValueSeed {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserialize_value(deserializer)
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("nonfinite JSON number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        let length = sequence.size_hint();
        if let Some(length) = length {
            // The live borrowed Value iterator supplies its actual length.
            // Reserve that destination once instead of reproducing parser
            // growth. A failed request leaves no partially published output.
            values
                .try_reserve_exact(length)
                .map_err(|_| de::Error::custom("JSON array storage unavailable"))?;
            if values.capacity() != length {
                return Err(de::Error::custom("JSON array storage changed"));
            }
        }
        while let Some(value) = sequence.next_element_seed(ValueSeed)? {
            if length.is_some_and(|length| values.len() == length) {
                return Err(de::Error::custom("JSON array length changed"));
            }
            values.push(value);
        }
        if length.is_some_and(|length| values.len() != length) {
            return Err(de::Error::custom("JSON array length changed"));
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Value, A::Error> {
        ObjectVisitor::<Map<String, Value>>(PhantomData)
            .visit_map(map)
            .map(Value::Object)
    }
}

trait Object: Default {
    fn insert(&mut self, key: String, value: Value) -> Option<Value>;
}

impl Object for Map<String, Value> {
    fn insert(&mut self, key: String, value: Value) -> Option<Value> {
        self.insert(key, value)
    }
}

impl Object for BTreeMap<String, Value> {
    fn insert(&mut self, key: String, value: Value) -> Option<Value> {
        self.insert(key, value)
    }
}

struct ObjectVisitor<T>(PhantomData<T>);

impl<'de, T: Object> Visitor<'de> for ObjectVisitor<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<T, A::Error> {
        let mut values = T::default();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(ValueSeed)?;
            if values.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(values)
    }
}

struct OptionalObjectVisitor;

impl<'de> Visitor<'de> for OptionalObjectVisitor {
    type Value = Option<Map<String, Value>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map or null")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        ObjectVisitor::<Map<String, Value>>(PhantomData)
            .visit_map(map)
            .map(Some)
    }
}

#[cfg(test)]
mod tests;
