//! Bounded closed runtime envelope validation before credentials or other effects.

use anyhow::{Result, bail};
use aos_contract::limits::{BoundedWriter, JsonLimits};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

pub(crate) const ENVELOPE_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 256 * 1024,
    max_depth: 32,
    max_items: 16_384,
    max_string_bytes: 8 * 1024,
};

pub(crate) fn text(value: &str, maximum: usize, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        bail!("{label} requires bounded nonempty text without controls");
    }
    Ok(())
}

pub(crate) fn sorted<T: Ord>(values: &[T], label: &str) -> Result<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("{label} must be sorted and unique");
    }
    Ok(())
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T> {
    let value: Value = ENVELOPE_LIMITS.decode(bytes, label)?;
    reject_null(&value)?;
    Ok(serde_json::from_value(value)?)
}

pub(crate) fn reject_null(value: &Value) -> Result<()> {
    match value {
        Value::Null => bail!("optional runtime fields must be absent rather than null"),
        Value::Array(values) => values.iter().try_for_each(reject_null),
        Value::Object(values) => values.values().try_for_each(reject_null),
        _ => Ok(()),
    }
}

pub(crate) fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bound = BoundedWriter::new(
        ENVELOPE_LIMITS.max_bytes as u64,
        "runtime envelope exceeds byte limit",
    );
    serde_json::to_writer(&mut bound, value)?;
    let value = serde_json::to_value(value)?;
    ENVELOPE_LIMITS.check_value(&value, "runtime envelope")?;
    reject_null(&value)?;
    aos_contract::canonical::to_vec(&value)
}

pub(crate) mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let value = encoded.parse::<u64>().map_err(serde::de::Error::custom)?;
        if encoded != value.to_string() || value == 0 || value > 9_007_199_254_740_991 {
            return Err(serde::de::Error::custom(
                "revision requires a positive canonical portable decimal string",
            ));
        }
        Ok(value)
    }
}
