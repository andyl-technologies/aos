//! Precredits closed package metadata rosters before typed reconstruction.

use crucible_node_contract::canonical;
use serde_json::Value;

use super::super::{NodeObservedError, refused};

/// Returns a bounded canonical object without interpreting source authority.
pub(super) fn canonical_object(bytes: &[u8], maximum: usize) -> Result<Value, NodeObservedError> {
    let value = canonical::parse_json(bytes, maximum)?;
    if !value.is_object() || canonical::canonical_json(&value)? != bytes {
        return Err(refused("typed reader metadata requires a canonical object"));
    }
    Ok(value)
}

/// Checks an exact borrowed role map before any typed path or ContentRef copy.
pub(super) fn keys(value: &Value, field: &str, expected: &[&str]) -> Result<(), NodeObservedError> {
    let object = value
        .as_object()
        .and_then(|root| root.get(field))
        .and_then(Value::as_object)
        .ok_or_else(|| refused("typed reader metadata role map missing"))?;
    if !object
        .keys()
        .map(String::as_str)
        .eq(expected.iter().copied())
    {
        return Err(refused("typed reader metadata role roster differs"));
    }
    Ok(())
}

/// Checks a borrowed array count before cloning any member into typed records.
pub(super) fn array(
    value: &Value,
    field: &str,
    maximum: usize,
) -> Result<usize, NodeObservedError> {
    let array = value
        .as_object()
        .and_then(|root| root.get(field))
        .and_then(Value::as_array)
        .ok_or_else(|| refused("typed reader metadata array missing"))?;
    if array.len() > maximum {
        return Err(refused("typed reader metadata entry credit exceeded"));
    }
    Ok(array.len())
}
