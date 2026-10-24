//! Borrows the closed native-after confirmation extension without owning copies.
//!
//! These views validate only syntax and exact field correspondence. The selected
//! installed codec, original correlation, literal history and source issuer remain
//! separate requirements. No deserializer, hashing callback or heap is used here.

use crate::ProviderError;
use crate::envelope::{Envelope, MessageKind, Method};
use serde_json::{Map, Value};

const FEATURE: &str = "source-owned.packet-native-after-confirmation/5";
const REQUEST: &str = "source-owned.packet-native-after-confirmation-request/5";
const RECEIPT: &str = "source-owned.packet-native-after-confirmation-receipt/5";
const TERMINAL_DOMAIN: &str = "source-owned.packet-native-capture-terminal/5";

fn invalid() -> ProviderError {
    ProviderError::Correlation("native-after borrowed confirmation grammar")
}

fn object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, ProviderError> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(object)
}

fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, ProviderError> {
    object.get(name).ok_or_else(invalid)
}

fn text<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, ProviderError> {
    field(object, name)?.as_str().ok_or_else(invalid)
}

fn identifier(value: &str) -> Result<(), ProviderError> {
    if !value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return Err(invalid());
    }
    Ok(())
}

fn integer(value: &Value) -> Result<u64, ProviderError> {
    let value = value.as_str().ok_or_else(invalid)?;
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    value.parse().map_err(|_| invalid())
}

fn hash(value: &Value, domain: &str) -> Result<(), ProviderError> {
    let object = object(value, &["algorithm", "domain", "digest"])?;
    let digest = text(object, "digest")?;
    if text(object, "algorithm")? != "blake3-256"
        || text(object, "domain")? != domain
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    Ok(())
}

fn content(value: &Value) -> Result<u64, ProviderError> {
    let object = object(value, &["hash", "length", "media_type"])?;
    hash(field(object, "hash")?, "cnp.blob.v1")?;
    let media = text(object, "media_type")?;
    if media.is_empty()
        || media.len() > 128
        || !media.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(invalid());
    }
    integer(field(object, "length")?)
}

/// Retains borrowed closed data from an actual request or receipt extension.
pub(crate) struct ConfirmationProjection<'a> {
    pub(crate) capture: &'a Value,
    pub(crate) capture_operation_id: &'a str,
    pub(crate) after: Option<&'a Value>,
}

impl<'a> ConfirmationProjection<'a> {
    fn request(value: &'a Value) -> Result<Self, ProviderError> {
        let object = object(
            value,
            &[
                "schema",
                "capture_request_id",
                "capture_request_hash",
                "capture_operation_id",
                "capture_terminal_hash",
                "capture_terminal_sequence",
                "native_snapshot_ref",
                "native_control_ref",
                "native_anchor_ref",
            ],
        )?;
        let request_id = text(object, "capture_request_id")?;
        let operation_id = text(object, "capture_operation_id")?;
        identifier(request_id)?;
        identifier(operation_id)?;
        hash(field(object, "capture_request_hash")?, "cnp.request.v1")?;
        hash(field(object, "capture_terminal_hash")?, TERMINAL_DOMAIN)?;
        let snapshot = field(object, "native_snapshot_ref")?;
        let control = field(object, "native_control_ref")?;
        let anchor = field(object, "native_anchor_ref")?;
        content(snapshot)?;
        content(control)?;
        content(anchor)?;
        if text(object, "schema")? != REQUEST
            || integer(field(object, "capture_terminal_sequence")?)? == 0
            || snapshot == control
            || snapshot == anchor
            || control == anchor
        {
            return Err(invalid());
        }
        Ok(Self {
            capture: value,
            capture_operation_id: operation_id,
            after: None,
        })
    }

    /// Checks the one closed envelope extension and immutable Poll scope.
    pub(crate) fn from_envelope(envelope: &'a Envelope) -> Result<Self, ProviderError> {
        if envelope.method != Method::Poll
            || envelope.extensions.len() != 1
            || envelope.execution_owner_id.0.is_some()
            || envelope.capture_owner_id.0.is_none()
            || envelope.node_id.0.is_none()
            || envelope.request_id.0.is_none()
            || envelope
                .body
                .get("extensions")
                .and_then(Value::as_object)
                .is_none_or(|v| !v.is_empty())
        {
            return Err(invalid());
        }
        let value = envelope.extensions.get(FEATURE).ok_or_else(invalid)?;
        let projection = match envelope.message {
            MessageKind::Request => Self::request(value)?,
            MessageKind::Response => {
                let object = object(
                    value,
                    &[
                        "schema",
                        "capture",
                        "native_after_ref",
                        "native_after_capacity",
                    ],
                )?;
                let mut projection = Self::request(field(object, "capture")?)?;
                let after = field(object, "native_after_ref")?;
                let length = content(after)?;
                let capture = projection.capture.as_object().ok_or_else(invalid)?;
                if text(object, "schema")? != RECEIPT
                    || integer(field(object, "native_after_capacity")?)? < length
                    || [
                        "native_snapshot_ref",
                        "native_control_ref",
                        "native_anchor_ref",
                    ]
                    .iter()
                    .any(|key| capture.get(*key) == Some(after))
                {
                    return Err(invalid());
                }
                projection.after = Some(after);
                projection
            }
            MessageKind::Event => return Err(invalid()),
        };
        if envelope.operation_id.0.as_ref().map(|id| id.as_str())
            != Some(projection.capture_operation_id)
        {
            return Err(invalid());
        }
        if envelope.message == MessageKind::Request
            && envelope.request_id.0.as_ref().map(|id| id.as_str())
                == projection
                    .capture
                    .get("capture_request_id")
                    .and_then(Value::as_str)
        {
            return Err(invalid());
        }
        Ok(projection)
    }
}

/// Checks the baseline typed body alongside the borrowed extension projection.
pub(super) fn validate_typed_poll(
    envelope: &Envelope,
    body: &crate::connection::ReceivedBody,
) -> Result<(), ProviderError> {
    use crate::{
        bodies::{MethodResult, OperationState, RequestBody, ResponseShape},
        connection::ReceivedBody,
    };
    match (envelope.message, body) {
        (MessageKind::Request, ReceivedBody::Request(request)) => {
            let RequestBody::Poll(poll) = request.as_ref() else {
                return Err(invalid());
            };
            if poll.after_observation_sequence.get() != 0 || !poll.extensions.is_empty() {
                return Err(invalid());
            }
        }
        (MessageKind::Response, ReceivedBody::Response(response)) => {
            if !matches!(
                response.shape,
                ResponseShape::Completed {
                    operation_state: OperationState::Completed,
                    ..
                }
            ) || !matches!(&response.result, Some(MethodResult::Poll(poll)) if poll.observations.is_empty() && poll.next_observation_sequence.get() == 0)
            {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- These closed data controls deliberately panic on malformed test fixtures.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use serde_json::json;

    fn reference(digest: char) -> Value {
        json!({"hash":{"algorithm":"blake3-256","domain":"cnp.blob.v1","digest":digest.to_string().repeat(64)},"length":"4","media_type":"application/json"})
    }

    fn request() -> Envelope {
        serde_json::from_value(json!({
            "protocol":"CNP/1","message":"request","method":"poll",
            "session_id":"session","incarnation_id":"native","node_id":"node",
            "execution_owner_id":null,"capture_owner_id":"capture","request_id":"confirm",
            "operation_id":"operation","sequence":"3",
            "body":{"after_observation_sequence":"0","extensions":{}},
            "extensions":{FEATURE:{
                "schema":REQUEST,"capture_request_id":"original-capture","capture_operation_id":"operation",
                "capture_request_hash":{"algorithm":"blake3-256","domain":"cnp.request.v1","digest":"a".repeat(64)},
                "capture_terminal_hash":{"algorithm":"blake3-256","domain":TERMINAL_DOMAIN,"digest":"b".repeat(64)},
                "capture_terminal_sequence":"22","native_snapshot_ref":reference('c'),
                "native_control_ref":reference('d'),"native_anchor_ref":reference('e')
            }}
        })).unwrap()
    }

    #[test]
    fn confirmation_projection_borrows_closed_request_and_receipt_without_a_dto() {
        let mut original = request();
        let projection = ConfirmationProjection::from_envelope(&original).unwrap();
        assert!(std::ptr::eq(
            projection.capture,
            &original.extensions[FEATURE]
        ));
        assert_eq!(projection.capture_operation_id, "operation");
        assert!(projection.after.is_none());

        let capture = original.extensions[FEATURE].clone();
        original.message = MessageKind::Response;
        original.extensions.insert(
            FEATURE.into(),
            json!({"schema":RECEIPT,"capture":capture,
            "native_after_ref":reference('f'),"native_after_capacity":"64"}),
        );
        let projection = ConfirmationProjection::from_envelope(&original).unwrap();
        assert!(std::ptr::eq(
            projection.after.unwrap(),
            &original.extensions[FEATURE]["native_after_ref"]
        ));

        original.extensions.get_mut(FEATURE).unwrap()["native_after_capacity"] = json!("3");
        assert!(ConfirmationProjection::from_envelope(&original).is_err());
    }

    #[test]
    fn confirmation_projection_refuses_hostile_closed_field_and_scope_changes() {
        for (field, value) in [
            ("capture_request_id", json!(".invalid")),
            ("capture_terminal_sequence", json!("01")),
            ("capture_terminal_sequence", json!("18446744073709551616")),
            ("schema", json!("another-dialect")),
            ("unrecognized", json!({"deep":[1,2,3]})),
        ] {
            let mut original = request();
            original.extensions.get_mut(FEATURE).unwrap()[field] = value;
            assert!(ConfirmationProjection::from_envelope(&original).is_err());
        }
        let mut original = request();
        original.operation_id.0 = Some(crucible_node_format::Id::new("another-operation").unwrap());
        assert!(ConfirmationProjection::from_envelope(&original).is_err());

        let mut original = request();
        original.extensions.get_mut(FEATURE).unwrap()["native_control_ref"] = reference('c');
        assert!(ConfirmationProjection::from_envelope(&original).is_err());

        let mut original = request();
        original.extensions.get_mut(FEATURE).unwrap()["capture_terminal_hash"]["domain"] =
            json!("cnp.request.v1");
        assert!(ConfirmationProjection::from_envelope(&original).is_err());
    }
}
