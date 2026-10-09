//! Shared structural bounds for canonical assessment records.

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use aos_contract::limits::JsonLimits;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

/// Limits a normalized immutable assessment document before admission.
pub const DOCUMENT_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 16 * 1024 * 1024,
    max_depth: 32,
    max_items: 250_000,
    max_string_bytes: 8 * 1024,
};

/// Rejects null members before optional fields can lose their wire identity.
pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T> {
    let value: Value = DOCUMENT_LIMITS.decode(bytes, label)?;
    reject_null(&value)?;
    serde_json::from_value(value).map_err(|error| anyhow::anyhow!("invalid {label}: {error}"))
}

fn reject_null(value: &Value) -> Result<()> {
    match value {
        Value::Null => bail!("assessment optional members must be absent, not null"),
        Value::Array(items) => {
            for item in items {
                reject_null(item)?;
            }
        }
        Value::Object(fields) => {
            for item in fields.values() {
                reject_null(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validates a bounded nonempty public identifier or text field.
pub(crate) fn text(value: &str, maximum: usize, field: &str) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        bail!("invalid assessment {field}");
    }
    Ok(())
}

/// Requires a strictly ordered set without silently changing its identity.
pub(crate) fn sorted<T: Ord>(values: &[T], field: &str) -> Result<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("assessment {field} must be sorted and unique");
    }
    Ok(())
}

/// Computes a domain-separated bounded object identity.
pub(crate) fn digest<T: Serialize>(schema: &str, object: &T) -> Result<Sha256Digest> {
    let bytes = aos_contract::canonical::to_vec(object)?;
    if bytes.len() > DOCUMENT_LIMITS.max_bytes {
        bail!("assessment object exceeds byte limit");
    }
    DOCUMENT_LIMITS.check_value(&serde_json::to_value(object)?, schema)?;
    Ok(Sha256Digest::separated(schema, bytes))
}
