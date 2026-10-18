//! Bounds the selected signed Observe17 terminal before allocating method DTOs.
//!
//! The ordinary frame reader already retains and bounds the whole raw JSON DOM.
//! This allocation-free roster check separately bounds the subsequent selected
//! method DTO. It verifies grammar only: MAC, native completion, exact expected
//! inventory and currentness remain independently authenticated by their owners.

use super::*;
use crate::reference_packet::service::restored_input_reactive17::RESTORED_INPUT_REACTIVE17_FEATURE;
use serde_json::{Map, Value};
use std::mem::size_of;

fn refused() -> ProviderError {
    ProviderError::Correlation("signed Observe17 terminal exceeds its closed typed roster")
}

fn fields<'a>(value: &'a Value, names: &[&str]) -> Result<&'a Map<String, Value>, ProviderError> {
    let value = value.as_object().ok_or_else(refused)?;
    if value.len() != names.len() || names.iter().any(|name| !value.contains_key(*name)) {
        return Err(refused());
    }
    Ok(value)
}

fn text(value: &Value, maximum: usize) -> Result<&str, ProviderError> {
    value
        .as_str()
        .filter(|text| text.len() <= maximum)
        .ok_or_else(refused)
}

fn empty_object(value: &Value) -> Result<(), ProviderError> {
    if value.as_object().is_none_or(|value| !value.is_empty()) {
        return Err(refused());
    }
    Ok(())
}

fn integer(value: &Value) -> Result<(), ProviderError> {
    // The contract's U64 fields use decimal strings. Semantic decimal spelling
    // and range are still checked by their defining deserializer.
    text(value, 20)?;
    Ok(())
}

fn hash(value: &Value) -> Result<(), ProviderError> {
    let value = fields(value, &["algorithm", "domain", "digest"])?;
    text(&value["algorithm"], 32)?;
    text(&value["domain"], 128)?;
    text(&value["digest"], 128)?;
    Ok(())
}

fn reference(value: &Value) -> Result<(), ProviderError> {
    let value = fields(value, &["hash", "length", "media_type"])?;
    hash(&value["hash"])?;
    integer(&value["length"])?;
    text(&value["media_type"], 128)?;
    Ok(())
}

fn batch(value: &Value) -> Result<(), ProviderError> {
    let value = fields(
        value,
        &[
            "schema_version",
            "execution_owner_id",
            "owner_binding_hash",
            "world_binding_hash",
            "activation_id",
            "world_generation",
            "owner_generation",
            "operation_id",
            "grant_id",
            "first_sequence",
            "last_sequence",
            "events",
            "visibility",
            "measurement_ref",
            "extensions",
        ],
    )?;
    // Version is numeric, rather than the decimal-string U64 wire type.
    if value["schema_version"].as_u64() != Some(1)
        || !value["grant_id"].is_null()
        || value["events"]
            .as_array()
            .is_none_or(|events| !events.is_empty())
    {
        return Err(refused());
    }
    for name in ["execution_owner_id", "activation_id", "operation_id"] {
        text(&value[name], 128)?;
    }
    for name in [
        "world_generation",
        "owner_generation",
        "first_sequence",
        "last_sequence",
    ] {
        integer(&value[name])?;
    }
    hash(&value["owner_binding_hash"])?;
    hash(&value["world_binding_hash"])?;
    reference(&value["measurement_ref"])?;
    text(&value["visibility"], 32)?;
    empty_object(&value["extensions"])
}

/// Checks only the actual distinct signed Observe original's selected roster.
///
/// # Errors
/// Refuses a mismatched response or a selected terminal whose successful typed
/// population is not the exact one-empty-batch grammar. Error details remain
/// arbitrary bounded raw JSON and are priced independently by the receiver.
pub(super) fn authenticate_original_class_data(
    original: &Envelope,
    response: &Envelope,
) -> Result<(), ProviderError> {
    let selected =
        Connection::<crate::client::DeadlineStream>::is_original_restored_observation17_data(
            original,
        );
    if !selected {
        return Ok(());
    }
    original.matches_response(response)?;
    if !response.extensions.is_empty() {
        return Err(refused());
    }
    let body = &response.body;
    match body.get("status").and_then(Value::as_str) {
        Some("completed") => {
            if body.len() != 4
                || body.get("operation_state").and_then(Value::as_str) != Some("completed")
            {
                return Err(refused());
            }
            empty_object(body.get("extensions").ok_or_else(refused)?)?;
            let result = fields(
                body.get("result").ok_or_else(refused)?,
                &[
                    "observations",
                    "next_sequence",
                    "complete",
                    "inventory_hash",
                ],
            )?;
            let observations = result["observations"].as_array().ok_or_else(refused)?;
            let [observation] = observations.as_slice() else {
                return Err(refused());
            };
            if !result["complete"].is_boolean() {
                return Err(refused());
            }
            integer(&result["next_sequence"])?;
            hash(&result["inventory_hash"])?;
            batch(observation)
        }
        Some("error") => {
            if body.len() != 4 {
                return Err(refused());
            }
            text(body.get("operation_state").ok_or_else(refused)?, 32)?;
            empty_object(body.get("extensions").ok_or_else(refused)?)?;
            let error = fields(
                body.get("error").ok_or_else(refused)?,
                &["code", "message", "effect", "retryable", "details"],
            )?;
            text(&error["code"], 128)?;
            text(&error["message"], 4096)?;
            text(&error["effect"], 32)?;
            if !error["retryable"].is_boolean() || !error["details"].is_object() {
                return Err(refused());
            }
            Ok(())
        }
        _ => Err(refused()),
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<[&str; 15]>()
        + size_of::<[&str; 5]>()
        + size_of::<[&str; 4]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<&Envelope>() * 2
        + size_of::<&Map<String, Value>>() * 4
        + size_of::<Option<&Value>>()
        + size_of::<Option<&str>>()
        + size_of::<Result<&str, ProviderError>>()
        + size_of::<Result<&Map<String, Value>, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

impl<S: ProviderStream> Connection<S> {
    /// Selects transport grammar without authenticating any action authority.
    pub(crate) fn is_original_restored_observation17_data(original: &Envelope) -> bool {
        original.method == Method::Observe
            && original.extensions.len() == 1
            && original
                .extensions
                .get(RESTORED_INPUT_REACTIVE17_FEATURE)
                .and_then(|artifact| artifact.get("request"))
                .and_then(|request| request.get("command"))
                .and_then(|command| command.get("action"))
                .and_then(Value::as_str)
                == Some("observe")
    }

    /// Retains a selected terminal before any fallible roster or typed decode.
    ///
    /// `None` denotes a successfully retained terminal; `Some` returns ordinary
    /// provider-origin content traffic to the same caller's unchanged drain.
    /// Refusal leaves an initialized terminal in the actual SDK attempt, while
    /// the literal bank independently preserves its original framed bytes.
    ///
    /// # Errors
    /// Refuses an unsupported original, occupied destinations, revoked actor,
    /// EOF, changed correlation, malformed roster/DTO or failed journal guard.
    pub(crate) fn receive_original_restored_observation17_into(
        &mut self,
        original: &Envelope,
        terminal: &mut Option<Envelope>,
        decoded: &mut Option<Box<ResponseBody>>,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        if !Self::is_original_restored_observation17_data(original)
            || terminal.is_some()
            || decoded.is_some()
            || self.role != EndpointRole::Controller
        {
            return Err(refused());
        }
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        self.authenticate_native5_source_codec()?;
        if self
            .guard
            .pending_requests()
            .find(|pending| pending.request_id == original.request_id)
            != Some(original)
        {
            return Err(refused());
        }
        let result = (|| {
            let Some(value) = self.reader.read()? else {
                self.contain(ConnectionFailure::Read);
                return Err(refused());
            };
            let envelope: Envelope = serde_json::from_value(value)
                .map_err(crucible_node_contract::ContractError::from)?;
            if envelope.message == MessageKind::Response {
                *terminal = Some(envelope);
                let envelope = terminal.as_ref().ok_or_else(refused)?;
                original.matches_response(envelope)?;
                let ReceivedBody::Response(body) = self.validate_body(envelope, true)? else {
                    return Err(refused());
                };
                *decoded = Some(body);
                self.retain_original_request_id(envelope, self.reader.original_slot())?;
                self.authority.with_live(|| self.guard.receive(envelope))?;
                Ok(None)
            } else {
                // Only ordinary evidence transfers belong before this terminal.
                // Reject every other role at its retained literal cut before a
                // generic Retire/Notification DTO could allocate another roster.
                if envelope.message != MessageKind::Request
                    || !matches!(
                        envelope.method,
                        Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
                    )
                {
                    return Err(refused());
                }
                let body = self.validate_body(&envelope, true)?;
                self.retain_original_request_id(&envelope, self.reader.original_slot())?;
                self.authority.with_live(|| self.guard.receive(&envelope))?;
                Ok(Some(ReceivedFrame { envelope, body }))
            }
        })();
        if result.is_err() {
            self.contain(ConnectionFailure::Protocol);
        }
        result
    }

    pub(crate) fn original_restored_observation17_response_counter_scratch_data(&self) -> usize {
        counter_scratch_data()
            + std::mem::size_of_val(&self.guard.pending_requests())
            + std::mem::size_of_val(&self.guard.incoming_requests())
            + size_of::<Option<ReceivedFrame>>()
            + size_of::<Result<Option<ReceivedFrame>, ProviderError>>()
            + size_of::<ReceivedFrame>()
            + size_of::<ReceivedBody>()
            + size_of::<Option<Envelope>>()
            + size_of::<Option<Box<ResponseBody>>>()
            + size_of::<Result<Option<Value>, ProviderError>>()
            + size_of::<Result<Envelope, serde_json::Error>>()
            + size_of::<Result<ReceivedBody, ProviderError>>()
            + size_of::<Option<&Envelope>>()
            + size_of::<&mut Option<Envelope>>()
            + size_of::<&mut Option<Box<ResponseBody>>>()
    }
}

// crucible-lint: allow panic-shortcut -- These controls exercise borrowed grammar DATA, never a live admission or completion.
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn selected() -> Envelope {
        let mut original = crate::envelope::tests::request();
        original.method = Method::Observe;
        original.extensions.clear();
        original.extensions.insert(
            RESTORED_INPUT_REACTIVE17_FEATURE.into(),
            json!({"request":{"command":{"action":"observe"}}}),
        );
        original
    }

    fn hash_value() -> Value {
        json!({"algorithm":"blake3-256","domain":"test.domain","digest":"0".repeat(64)})
    }

    fn completed(original: &Envelope) -> Envelope {
        let hash = hash_value();
        let mut response = original.clone();
        response.message = MessageKind::Response;
        response.extensions.clear();
        response.body = json!({
            "status":"completed","operation_state":"completed","extensions":{},
            "result":{
                "observations":[{
                    "schema_version":1,"execution_owner_id":"owner",
                    "owner_binding_hash":hash,"world_binding_hash":hash,
                    "activation_id":"activation","world_generation":"1",
                    "owner_generation":"1","operation_id":"request",
                    "grant_id":null,"first_sequence":"0","last_sequence":"0",
                    "events":[],"visibility":"staged",
                    "measurement_ref":{"hash":hash,"length":"1","media_type":"application/json"},
                    "extensions":{}
                }],
                "next_sequence":"1","complete":true,"inventory_hash":hash
            }
        })
        .as_object()
        .unwrap()
        .clone();
        response
    }

    #[test]
    fn selected_roster_rejects_extra_batches_events_and_unbounded_leaf_fields() {
        let original = selected();
        let response = completed(&original);
        authenticate_original_class_data(&original, &response).unwrap();

        let mut extra_batch = response.clone();
        let observations = extra_batch.body.get_mut("result").unwrap()["observations"]
            .as_array_mut()
            .unwrap();
        observations.push(observations[0].clone());
        assert!(authenticate_original_class_data(&original, &extra_batch).is_err());

        let mut extra_event = response.clone();
        extra_event.body.get_mut("result").unwrap()["observations"][0]["events"] =
            json!([{"not":"an Event DTO"}]);
        assert!(authenticate_original_class_data(&original, &extra_event).is_err());

        let mut oversized_id = response.clone();
        oversized_id.body.get_mut("result").unwrap()["observations"][0]["execution_owner_id"] =
            Value::String("x".repeat(129));
        assert!(authenticate_original_class_data(&original, &oversized_id).is_err());

        let mut extra_field = response.clone();
        extra_field.body.get_mut("result").unwrap()["observations"][0]["future_field"] =
            Value::Null;
        assert!(authenticate_original_class_data(&original, &extra_field).is_err());
    }

    #[test]
    fn selected_errors_keep_arbitrary_raw_details_but_bound_typed_error_strings() {
        let original = selected();
        let mut response = original.clone();
        response.message = MessageKind::Response;
        response.extensions.clear();
        response.body = json!({
            "status":"error","operation_state":"unknown","extensions":{},
            "error":{"code":"OUTCOME_UNKNOWN","message":"x".repeat(4096),
                     "effect":"unknown","retryable":false,
                     "details":{"arbitrary":[{"untrusted":"raw metadata"},[1,2,3]]}}
        })
        .as_object()
        .unwrap()
        .clone();
        authenticate_original_class_data(&original, &response).unwrap();

        response.body.get_mut("error").unwrap()["message"] = Value::String("x".repeat(4097));
        assert!(authenticate_original_class_data(&original, &response).is_err());
    }

    #[test]
    fn ordinary_observe_and_input_classes_keep_their_existing_grammar() {
        let mut original = selected();
        let mut response = completed(&original);
        response.body.clear();
        original.extensions.clear();
        authenticate_original_class_data(&original, &response).unwrap();

        original = selected();
        original.method = Method::Input;
        authenticate_original_class_data(&original, &response).unwrap();
    }
}
