//! Checks the genuine pending-to-completed Capture entry in both Control owners.

use super::*;
use crate::{
    bodies::{BeginKind, CaptureArguments},
    envelope::{Envelope, MessageKind, RequestOrigin},
};

impl CurrentControl17Data {
    /// Joins the actual registration identity and exact single cached transition.
    ///
    /// Every unrelated model queue, operation and reply remains untouched. The
    /// final confirmation is a later Endpoint transaction; no future Poll reply
    /// is required in either Control cache by this comparison.
    ///
    /// # Errors
    /// Refuses foreign identity/scope, a changed Begin/original, absent pending
    /// unknown custody or a completed native reply different from the SDK pair.
    pub(crate) fn authenticate_capture_settlement17_data(
        &self,
        after: &Self,
        original: &Envelope,
        arguments: &CaptureArguments,
        begin: &BeginRequest,
        terminal: &Envelope,
        registration_identity: usize,
    ) -> Result<(), ProviderError> {
        original.validate()?;
        terminal.validate()?;
        original.matches_response(terminal)?;

        let id = original.request_id.0.as_ref().ok_or_else(invalid)?;
        let operation = original.operation_id.0.as_ref().ok_or_else(invalid)?;
        let binding = self
            .selection
            .realization
            .bindings
            .first()
            .ok_or_else(invalid)?;
        let owner = self
            .selection
            .realization
            .owner_bindings
            .first()
            .ok_or_else(invalid)?;
        let active = self.active.as_ref().ok_or_else(invalid)?;
        if original.session_id.0.as_ref() != Some(&binding.authority.session_id)
            || original.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
            || original.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
            || original.capture_owner_id.0.as_ref() != Some(&binding.compatibility.capture_owner.id)
            || original.execution_owner_id.0.is_some()
            || begin.binding_hash != owner.identity()?
            || begin.owner_generation != binding.authority.owner_generation
            || arguments.participant_ids != owner.owner.participant_ids
            || begin.activation_id.0.as_ref() != Some(&active.activation_id)
            || begin.world_generation != active.world_generation
            || active.world_binding_hash != self.selection.world
        {
            return Err(invalid());
        }

        let identity = original.request_hash(RequestOrigin::Controller)?;
        let before_reply = self.originals_data().get(id).ok_or_else(invalid)?;
        let after_reply = after.originals_data().get(id).ok_or_else(invalid)?;
        if original.message != MessageKind::Request
            || original.method != Method::Begin
            || terminal.message != MessageKind::Response
            || !terminal.extensions.is_empty()
            || begin.kind != BeginKind::Capture
            || !begin.extensions.is_empty()
            || self.capture_identity_role.group != registration_identity
            || self.capture_creator == 0
            || self.capture_creator != after.capture_creator
            || self.selection != after.selection
            || self.active != after.active
            || self.fenced
            || after.fenced
            || !self.immediate
            || !after.immediate
            || self.restoration_activation_required
            || after.restoration_activation_required
            || self.staged.is_some()
            || after.staged.is_some()
            || self.current_operation.as_ref() != Some(operation)
            || after.current_operation.is_some()
            || self.begins.get(operation) != Some(begin)
            || after.begins.get(operation) != Some(begin)
            || self.begin_requests.get(operation) != Some(id)
            || after.begin_requests.get(operation) != Some(id)
            || self.terminals.contains_key(operation)
            || after.terminals.get(operation) != Some(&terminal.body)
            || before_reply.0 != identity
            || after_reply.0 != identity
            || !before_reply.1.evidence.is_empty()
            || !after_reply.1.evidence.is_empty()
            || after_reply.1.body != terminal.body
        {
            return Err(invalid());
        }

        // These temporary serialized objects are sequential Source-funded
        // comparison scratch, not retained native history or a permission.
        let begin_value =
            serde_json::to_value(begin).map_err(crucible_node_format::ContractError::from)?;
        if begin_value.as_object() != Some(&original.body) {
            return Err(invalid());
        }
        drop(begin_value);

        let arguments_value =
            serde_json::to_value(arguments).map_err(crucible_node_format::ContractError::from)?;
        if arguments_value.as_object() != Some(&begin.arguments) {
            return Err(invalid());
        }
        drop(arguments_value);
        pending_unknown(&before_reply.1.body)
    }
}

fn pending_unknown(body: &Map<String, Value>) -> Result<(), ProviderError> {
    fn text(body: &Map<String, Value>, name: &str, value: &str) -> bool {
        body.get(name).and_then(Value::as_str) == Some(value)
    }
    let error = body
        .get("error")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    if body.len() != 4
        || !text(body, "status", "error")
        || !text(body, "operation_state", "unknown")
        || body
            .get("extensions")
            .and_then(Value::as_object)
            .is_none_or(|value| !value.is_empty())
        || error.len() != 5
        || !text(error, "code", "OUTCOME_UNKNOWN")
        || !text(
            error,
            "message",
            "original native Capture remains unresolved",
        )
        || !text(error, "effect", "unknown")
        || error.get("retryable").and_then(Value::as_bool) != Some(false)
        || error
            .get("details")
            .and_then(Value::as_object)
            .is_none_or(|value| !value.is_empty())
    {
        return Err(invalid());
    }
    Ok(())
}
