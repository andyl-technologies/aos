//! Rejects arbitrary response trees before the closed Bootstrap18 DTO decoders.

use super::*;
use crucible_node_format::values::MAX_ID_BYTES;

pub(super) const ENVELOPE_FIELDS: [&str; 13] = [
    "protocol",
    "message",
    "session_id",
    "incarnation_id",
    "node_id",
    "execution_owner_id",
    "capture_owner_id",
    "request_id",
    "operation_id",
    "sequence",
    "method",
    "body",
    "extensions",
];
pub(super) const BODY_FIELDS: [&str; 4] = ["status", "operation_state", "result", "extensions"];
pub(super) const RESULT_FIELDS: [&str; 4] =
    ["schema", "state", "recipe_identity", "initial_funding"];
pub(super) const REQUEST_FIELDS: [&str; 3] = ["schema", "recipe_identity", "initial_funding"];
pub(super) const FUNDING_FIELDS: [&str; 3] = [
    "retained_requested_bytes",
    "maximum_simultaneous_transient_bytes",
    "declared_counter_scratch_bytes",
];
pub(super) const RECEIPT_FIELDS: [&str; 6] = [
    "schema",
    "algorithm",
    "state",
    "context_digest",
    "assigned_response",
    "mac",
];

pub(super) struct Closed<'a> {
    pub(super) result: &'a Value,
    pub(super) receipt: &'a Value,
}

pub(super) fn inspect_data<'a>(
    original: &Envelope,
    raw: &'a Value,
) -> Result<Closed<'a>, ProviderError> {
    if original.protocol != "CNP/1"
        || original.message != MessageKind::Request
        || original.method != Method::NativeImport18Bootstrap
        || original.sequence.get() != 2
        || original.session_id.0.is_none()
        || original.incarnation_id.0.is_none()
        || original.request_id.0.is_none()
        || original.node_id.0.is_some()
        || original.execution_owner_id.0.is_some()
        || original.capture_owner_id.0.is_some()
        || original.operation_id.0.is_some()
        || original.extensions.len() != 1
        || !original
            .extensions
            .contains_key(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)
    {
        return Err(refused());
    }
    roster(&original.body, &REQUEST_FIELDS)?;
    exact(
        &original.body,
        "schema",
        NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
    )?;
    width(&original.body, "recipe_identity", 43)?;
    funding(original.body.get("initial_funding").ok_or_else(refused)?)?;

    let root = object(raw, &ENVELOPE_FIELDS)?;
    exact(root, "protocol", "CNP/1")?;
    exact(root, "message", "response")?;
    exact(root, "method", "native_import18_bootstrap")?;
    exact(root, "sequence", "2")?;
    for (field, expected) in [
        ("session_id", original.session_id.0.as_ref()),
        ("incarnation_id", original.incarnation_id.0.as_ref()),
        ("request_id", original.request_id.0.as_ref()),
    ] {
        let expected = expected.ok_or_else(refused)?.as_str();
        if expected.is_empty() || expected.len() > MAX_ID_BYTES {
            return Err(refused());
        }
        exact(root, field, expected)?;
    }
    for field in [
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "operation_id",
    ] {
        if root.get(field).is_none_or(|value| !value.is_null()) {
            return Err(refused());
        }
    }

    let body = object(root.get("body").ok_or_else(refused)?, &BODY_FIELDS)?;
    exact(body, "status", "completed")?;
    exact(body, "operation_state", "completed")?;
    object(body.get("extensions").ok_or_else(refused)?, &[])?;
    let result = body.get("result").ok_or_else(refused)?;
    let fields = object(result, &RESULT_FIELDS)?;
    exact(fields, "schema", NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA)?;
    exact(fields, "state", "bootstrap_only")?;
    width(fields, "recipe_identity", 43)?;
    funding(fields.get("initial_funding").ok_or_else(refused)?)?;

    let extensions = object(
        root.get("extensions").ok_or_else(refused)?,
        &[NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT],
    )?;
    let receipt = extensions
        .get(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT)
        .ok_or_else(refused)?;
    let fields = object(receipt, &RECEIPT_FIELDS)?;
    exact(fields, "schema", NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT)?;
    exact(fields, "algorithm", PACKET_COMPLETE_RESTORE_ALGORITHM)?;
    exact(fields, "state", "bootstrap_only")?;
    for field in ["context_digest", "assigned_response", "mac"] {
        width(fields, field, 43)?;
    }
    Ok(Closed { result, receipt })
}

fn object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>, ProviderError> {
    let map = value.as_object().ok_or_else(refused)?;
    roster(map, fields)?;
    Ok(map)
}

fn roster(map: &Map<String, Value>, fields: &[&str]) -> Result<(), ProviderError> {
    if map.len() != fields.len() || fields.iter().any(|field| !map.contains_key(*field)) {
        return Err(refused());
    }
    Ok(())
}

fn exact(map: &Map<String, Value>, field: &str, expected: &str) -> Result<(), ProviderError> {
    if map.get(field).and_then(Value::as_str) != Some(expected) {
        return Err(refused());
    }
    Ok(())
}

fn width(map: &Map<String, Value>, field: &str, width: usize) -> Result<(), ProviderError> {
    if map
        .get(field)
        .and_then(Value::as_str)
        .is_none_or(|value| value.len() != width)
    {
        return Err(refused());
    }
    Ok(())
}

fn funding(value: &Value) -> Result<(), ProviderError> {
    for value in object(value, &FUNDING_FIELDS)?.values() {
        let value = value.as_str().ok_or_else(refused)?;
        if value.is_empty() || value.len() > 20 {
            return Err(refused());
        }
    }
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<Closed<'static>>()
        + size_of::<Result<Closed<'static>, ProviderError>>()
        + size_of::<[&str; 13]>()
        + size_of::<[&str; 4]>() * 3
        + size_of::<[&str; 3]>() * 3
        + size_of::<[&str; 6]>()
        + size_of::<[&str; 1]>()
        + size_of::<[(&str, Option<&Id>); 3]>()
        + size_of::<std::array::IntoIter<(&str, Option<&Id>), 3>>()
        + size_of::<std::array::IntoIter<&str, 4>>()
        + size_of::<std::array::IntoIter<&str, 3>>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<serde_json::map::Values<'static>>()
        + size_of::<[&Value; 5]>()
        + size_of::<[&Map<String, Value>; 6]>()
        + size_of::<[&str; 4]>()
        + size_of::<&[&str]>()
        + size_of::<Option<&Value>>()
        + size_of::<Option<&str>>()
        + size_of::<Option<&Id>>()
        + size_of::<[usize; 3]>()
        + size_of::<[Result<(), ProviderError>; 5]>()
}
