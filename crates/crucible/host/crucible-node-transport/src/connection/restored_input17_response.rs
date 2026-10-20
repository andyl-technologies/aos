//! Keeps the new Input17 result extension on its actual request class.
//!
//! Generic correlation alone cannot authorize a new response grammar on an old
//! Input4 original. The Connection calls this before result DTO allocation for
//! both incoming and outgoing responses. No MAC or action permission is issued.

use super::*;
use crate::reference_packet::service::restored_input_reactive17::RESTORED_INPUT_REACTIVE17_FEATURE;
use serde_json::Value;

pub(super) fn authenticate_original_class_data(
    original: &Envelope,
    response: &Envelope,
) -> Result<(), ProviderError> {
    if !response
        .body
        .get("extensions")
        .and_then(Value::as_object)
        .is_some_and(|extensions| extensions.contains_key(RESTORED_INPUT_REACTIVE17_FEATURE))
    {
        return Ok(());
    }
    original.matches_response(response)?;
    let command = original
        .extensions
        .get(RESTORED_INPUT_REACTIVE17_FEATURE)
        .and_then(|artifact| artifact.get("request"))
        .and_then(|request| request.get("command"))
        .and_then(|command| command.get("action"))
        .and_then(Value::as_str);
    if original.message != MessageKind::Request
        || original.method != Method::Input
        || original.extensions.len() != 1
        || command != Some("input")
    {
        return Err(ProviderError::Correlation(
            "Input17 response requires the actual Input17 original",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Nullable;
    use serde_json::json;

    #[test]
    fn result_extension_cannot_widen_an_old_or_mixed_input_original() {
        let mut original = crate::envelope::tests::request();
        original.method = Method::Input;
        original.extensions.clear();
        let mut response = original.clone();
        response.message = MessageKind::Response;
        response.body = json!({"extensions":{RESTORED_INPUT_REACTIVE17_FEATURE:{}}})
            .as_object()
            .unwrap()
            .clone();
        assert!(authenticate_original_class_data(&original, &response).is_err());

        original
            .extensions
            .insert("source-owned.packet-input/4".into(), json!({}));
        assert!(authenticate_original_class_data(&original, &response).is_err());
        original.extensions.insert(
            RESTORED_INPUT_REACTIVE17_FEATURE.into(),
            json!({
                "request":{"command":{"action":"input"}}
            }),
        );
        assert!(authenticate_original_class_data(&original, &response).is_err());
        original.extensions.remove("source-owned.packet-input/4");
        // This selects transport grammar only. The full schema, assigned
        // artifact, Source MAC and actual native action are independent checks.
        authenticate_original_class_data(&original, &response).unwrap();
        response.request_id = Nullable(Some(Id::new("different-input17-request").unwrap()));
        assert!(authenticate_original_class_data(&original, &response).is_err());
    }
}
