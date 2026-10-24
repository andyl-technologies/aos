//! Builds the response from the actual SDK sequence and retained typed result.

use super::*;

pub(super) fn build_data(
    original: &crate::envelope::Envelope,
    guard: &crate::session::CorrelationGuard,
    result: &ReplyResult,
) -> Result<crate::envelope::Envelope, ProviderError> {
    let sequence = guard.original_bootstrap_response_sequence_data(original)?;
    let mut body = serde_json::Map::new();
    body.insert(
        "status".into(),
        serde_json::Value::String("completed".into()),
    );
    body.insert(
        "operation_state".into(),
        serde_json::Value::String("completed".into()),
    );
    body.insert(
        "extensions".into(),
        serde_json::Value::Object(serde_json::Map::new()),
    );
    body.insert(
        "result".into(),
        serde_json::to_value(result).map_err(crucible_node_format::ContractError::from)?,
    );

    Ok(crate::envelope::Envelope {
        protocol: original.protocol.clone(),
        message: crate::envelope::MessageKind::Response,
        session_id: original.session_id.clone(),
        incarnation_id: original.incarnation_id.clone(),
        node_id: original.node_id.clone(),
        execution_owner_id: original.execution_owner_id.clone(),
        capture_owner_id: original.capture_owner_id.clone(),
        request_id: original.request_id.clone(),
        operation_id: original.operation_id.clone(),
        sequence,
        method: original.method,
        body,
        extensions: std::collections::BTreeMap::new(),
    })
}
