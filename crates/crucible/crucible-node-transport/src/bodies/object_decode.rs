//! Validates borrowed canonical body geometry before constructing a typed owner.
//!
//! Programmatic callers meet the same hard grammar and byte limits as decoded
//! traffic. Canonical validation retains neither a root DOM copy nor a whole
//! text bank. Typed decoding still owns its independent cloned input and result;
//! canonical ordering, formatting and diagnostics remain separately funded work.

use super::*;
use serde::de::DeserializeOwned;

const MAXIMUM_BODY_BYTES: usize = 16_777_216;

/// Decodes an independent typed body after borrowed canonical validation.
///
/// # Errors
/// Refuses canonical grammar or byte limits, typed schema decoding or local
/// validation. The borrowed input remains unchanged through every refusal.
pub(super) fn object<T: DeserializeOwned + Validate>(
    value: &Map<String, Value>,
) -> Result<T, ContractError> {
    if canonical::canonical_json_object_length_with_limit(value, MAXIMUM_BODY_BYTES)?.is_none() {
        return Err(invalid("body", "body exceeds hard frame ceiling"));
    }

    let decoded: T = serde_json::from_value(Value::Object(value.clone()))?;
    decoded.validate()?;
    Ok(decoded)
}

#[cfg(test)]
mod tests;
