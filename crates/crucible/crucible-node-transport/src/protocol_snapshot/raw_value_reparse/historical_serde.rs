//! Pins predecessor Serde field hooks for historical raw-value model oracles.
//!
//! These test-only remote derives preserve the old Value and nullable passes.
//! The live CNP types now preserve literal JSON instead. Reusing their current
//! Deserialize implementation would silently change the archived model's oracle.

use crate::bodies::{EffectCertainty, ErrorRecord, OperationState, ResponseShape};
use crate::envelope::{Envelope, MessageKind, Method, Nullable};
use crucible_node_format::{Extensions, Id, U64};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Map, Value};

/// Reproduces the predecessor envelope's exact Serde field schedule.
///
/// # Errors
/// Refuses inputs rejected by the historical closed schema or Value passes.
pub(super) fn decode_envelope(value: Value) -> Result<Envelope, serde_json::Error> {
    HistoricalEnvelope::deserialize(value)
}

/// Reproduces the predecessor tagged response and nested error field hooks.
///
/// # Errors
/// Refuses inputs rejected by the historical closed schema or Value passes.
pub(super) fn decode_response_shape(value: Value) -> Result<ResponseShape, serde_json::Error> {
    HistoricalResponseShape::deserialize(value)
}

fn deserialize_nullable<'de, D, T>(deserializer: D) -> Result<Nullable<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: DeserializeOwned,
{
    let value = Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(Nullable(None));
    }
    serde_json::from_value(value)
        .map(|value| Nullable(Some(value)))
        .map_err(serde::de::Error::custom)
}

// Remote derives construct the real output types without invoking their new
// field hooks. Their field initializers also detect additions to those types.
#[derive(Deserialize)]
#[serde(remote = "Envelope", deny_unknown_fields)]
struct HistoricalEnvelope {
    protocol: String,
    message: MessageKind,
    #[serde(deserialize_with = "deserialize_nullable")]
    session_id: Nullable<Id>,
    #[serde(deserialize_with = "deserialize_nullable")]
    incarnation_id: Nullable<Id>,
    #[serde(deserialize_with = "deserialize_nullable")]
    node_id: Nullable<Id>,
    #[serde(deserialize_with = "deserialize_nullable")]
    execution_owner_id: Nullable<Id>,
    #[serde(deserialize_with = "deserialize_nullable")]
    capture_owner_id: Nullable<Id>,
    #[serde(deserialize_with = "deserialize_nullable")]
    request_id: Nullable<Id>,
    #[serde(deserialize_with = "deserialize_nullable")]
    operation_id: Nullable<Id>,
    sequence: U64,
    method: Method,
    body: Map<String, Value>,
    extensions: Extensions,
}

#[derive(Deserialize)]
#[serde(
    remote = "ResponseShape",
    tag = "status",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum HistoricalResponseShape {
    Accepted {
        operation_state: OperationState,
        result: Map<String, Value>,
        extensions: Extensions,
    },
    Completed {
        operation_state: OperationState,
        result: Map<String, Value>,
        extensions: Extensions,
    },
    Error {
        operation_state: OperationState,
        #[serde(deserialize_with = "HistoricalErrorRecord::deserialize")]
        error: ErrorRecord,
        extensions: Extensions,
    },
}

#[derive(Deserialize)]
#[serde(remote = "ErrorRecord", deny_unknown_fields)]
struct HistoricalErrorRecord {
    code: String,
    message: String,
    effect: EffectCertainty,
    retryable: bool,
    details: Map<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn envelope(body: Value) -> Value {
        json!({
            "protocol":"CNP/1", "message":"response", "session_id":"session/0",
            "incarnation_id":"provider/0", "node_id":null,
            "execution_owner_id":null, "capture_owner_id":null,
            "request_id":"request/0", "operation_id":null, "sequence":"1",
            "method":"poll", "body":body, "extensions":{}
        })
    }

    #[test]
    fn historical_value_hooks_stay_distinct_from_the_live_literal_codec() -> TestResult {
        let marker = json!({"$serde_json::private::RawValue":"null"});
        let interpreted: Value = serde_json::from_value(marker.clone())?;
        let input = envelope(json!({"value":marker}));

        let historical = decode_envelope(input.clone())?;
        let live: Envelope = serde_json::from_value(input)?;

        assert_eq!(historical.body.get("value"), Some(&interpreted));
        assert_eq!(live.body.get("value"), Some(&marker));

        let response = json!({
            "status":"completed", "operation_state":"completed",
            "result":{"value":marker}, "extensions":{}
        });
        let historical = decode_response_shape(response.clone())?;
        let live: ResponseShape = serde_json::from_value(response.clone())?;

        assert_eq!(
            serde_json::to_value(historical)?["result"]["value"],
            interpreted
        );
        assert_eq!(serde_json::to_value(live)?, response);
        Ok(())
    }

    #[test]
    fn historical_nullable_hooks_preserve_the_old_marker_branch_only() -> TestResult {
        let mut input = envelope(json!({}));
        let marker = json!({"$serde_json::private::RawValue":"\"session/0\""});
        input["session_id"] = marker.clone();
        let interpreted: Value = serde_json::from_value(marker)?;

        let historical = decode_envelope(input.clone());
        let live = serde_json::from_value::<Envelope>(input);

        assert_eq!(historical.is_ok(), interpreted.is_string());
        assert!(live.is_err());
        Ok(())
    }
}
