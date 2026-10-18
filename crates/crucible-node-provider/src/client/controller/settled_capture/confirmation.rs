//! Assigns the separate fourth-object Poll after the same retained Capture.
//!
//! This owner keeps the original, raw reply, independently decoded Poll and
//! typed extension receipt through every refusal. Only the completed final
//! frontier releases the Controller's generic-request barrier.

use super::*;

impl PreparedOriginalRestoredSettledCapture<'_> {
    /// Retains and assigns the exact fourth-object confirmation once.
    ///
    /// # Errors
    /// Refuses another Capture tuple, reused ID, incomplete Capture or failed
    /// assignment. A failed confirmation cannot be replaced or restarted.
    pub fn prepare_confirmation_data(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        request: PacketRestoredSettledAfterConfirmationRequest,
    ) -> Result<(), ProviderError> {
        let controller = &mut *self.controller;
        controller.authenticate_restored_settled_capture_data(emitter)?;
        if controller.original(&request_id).is_some() {
            return Err(refused());
        }
        let maximum = controller.maximum_frame()?;
        let state = controller
            .original_restored_settled_capture
            .as_mut()
            .ok_or_else(refused)?;
        if super::request_id_reserved(state, &request_id)
            || state.stage != Stage::Captured
            || state.confirmation.is_some()
        {
            return Err(refused());
        }
        state.stage = Stage::Confirming;
        state.confirmation = Some(AssignedConfirmation {
            request_id,
            request,
            extension: None,
            original: None,
            cut: None,
            terminal: None,
            decoded: None,
            receipt: None,
            roots: Vec::new(),
            frontier: None,
            stage: ConfirmationStage::Preparing,
        });
        validate_capture_context(state)?;
        let confirmation = state.confirmation.as_mut().ok_or_else(refused)?;
        confirmation.request.validate_data()?;
        confirmation.extension = Some(
            serde_json::to_value(&confirmation.request)
                .map_err(crucible_node_contract::ContractError::from)?,
        );
        let mut extensions = Extensions::new();
        extensions.insert(
            PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE.into(),
            confirmation.extension.as_ref().ok_or_else(refused)?.clone(),
        );
        let (sequence, cut) = controller
            .session
            .begin_original_ack_admit(controller.budget)?;
        confirmation.cut = Some(cut);
        let body = PollRequest {
            after_observation_sequence: U64::new(0),
            extensions: Extensions::new(),
        };
        let node = Some(controller.route.node.clone());
        let owner = None;
        let operation = Some(state.operation_id.clone());
        let session = controller.session.authority().session_id().clone();
        let incarnation = controller.session.authority().incarnation_id().clone();
        count_serialized(
            &BorrowedEnvelope {
                protocol: "CNP/1",
                message: MessageKind::Request,
                session_id: &session,
                incarnation_id: &incarnation,
                node_id: &node,
                execution_owner_id: &owner,
                capture_owner_id: Some(&state.request.capture_owner),
                request_id: &confirmation.request_id,
                operation_id: &operation,
                sequence: U64::new(u64::MAX),
                method: Method::Poll,
                body: &body,
                extensions: &extensions,
            },
            maximum,
        )?;
        let Value::Object(body) =
            serde_json::to_value(&body).map_err(crucible_node_contract::ContractError::from)?
        else {
            return Err(refused());
        };
        confirmation.original = Some(Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(session)),
            incarnation_id: Nullable(Some(incarnation)),
            node_id: Nullable(node),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(Some(state.request.capture_owner.clone())),
            request_id: Nullable(Some(confirmation.request_id.clone())),
            operation_id: Nullable(operation),
            sequence,
            method: Method::Poll,
            body,
            extensions,
        });
        confirmation
            .original
            .as_ref()
            .ok_or_else(refused)?
            .validate()?;
        controller
            .session
            .authenticate_original_ack_admit_cut(sequence, cut)?;
        confirmation.stage = ConfirmationStage::Assigned;
        Ok(())
    }

    /// Publishes the same fourth-object Poll and retains every partial first.
    ///
    /// Actual provider-origin transfers must already place the fourth full
    /// reference in the content bank. No generic fetch is used to manufacture
    /// missing extension-content evidence while Capture is pending.
    ///
    /// # Errors
    /// Refuses uncertain IO, a changed Capture result, wrong typed receipt or
    /// missing hash-verified fourth bytes. Failure keeps the Controller blocked.
    pub fn publish_confirmation_data(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        let controller = &mut *self.controller;
        controller.authenticate_restored_settled_capture_data(emitter)?;
        let state = controller
            .original_restored_settled_capture
            .as_mut()
            .ok_or_else(refused)?;
        if state.stage != Stage::Confirming {
            return Err(refused());
        }
        validate_capture_context(state)?;
        let confirmation = state.confirmation.as_mut().ok_or_else(refused)?;
        if confirmation.stage != ConfirmationStage::Assigned {
            return Err(refused());
        }
        confirmation.stage = ConfirmationStage::Publishing;
        controller.session.publish_original_restored_suffix_into(
            &mut controller.custody,
            confirmation.original.as_ref().ok_or_else(refused)?,
            confirmation.cut.ok_or_else(refused)?,
            &mut confirmation.terminal,
            &mut confirmation.decoded,
        )?;
        let terminal = confirmation.terminal.as_ref().ok_or_else(refused)?;
        // Retain extension decoding before any equality/content/current checks.
        let extension = terminal
            .extensions
            .get(PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE)
            .ok_or_else(refused)?;
        confirmation.receipt = Some(
            serde::Deserialize::deserialize(extension)
                .map_err(crucible_node_contract::ContractError::from)?,
        );
        let receipt = confirmation.receipt.as_ref().ok_or_else(refused)?;
        receipt.validate_data()?;
        if receipt.capture != confirmation.request {
            return Err(refused());
        }
        let response = confirmation.decoded.as_deref().ok_or_else(refused)?;
        let Some(MethodResult::Poll(poll)) = response.result.as_ref() else {
            return Err(refused());
        };
        if !matches!(
            &response.shape,
            crate::bodies::ResponseShape::Completed {
                operation_state: crate::bodies::OperationState::Completed,
                ..
            }
        ) || poll.operation_id != state.operation_id
            || !poll.observations.is_empty()
            || poll.next_observation_sequence != U64::new(0)
            || poll.outcome.0.as_ref() != Some(&state.terminal.as_ref().ok_or_else(refused)?.body)
        {
            return Err(refused());
        }
        controller
            .custody
            .content()
            .get(&receipt.native_after_ref)?;
        confirmation.frontier = Some(controller.session.fresh_restore_query_sequence()?);
        validate_capture_context(state)?;
        controller.protocol_owner.ensure_current()?;
        state.confirmation.as_mut().ok_or_else(refused)?.stage = ConfirmationStage::Complete;
        state.stage = Stage::Complete;
        Ok(())
    }

    /// Borrows the actual fourth Poll original after assignment, including failure.
    ///
    /// # Errors
    /// Refuses a missing owner or assignment. This grants no archive permission.
    pub fn confirmation_original_data(&self) -> Result<&Envelope, ProviderError> {
        self.controller
            .original_restored_settled_capture
            .as_ref()
            .and_then(|state| state.confirmation.as_ref())
            .and_then(|confirmation| confirmation.original.as_ref())
            .ok_or_else(refused)
    }
}

fn validate_capture_context(state: &AssignedRestoredSettledCapture) -> Result<(), ProviderError> {
    let context = &state.confirmation.as_ref().ok_or_else(refused)?.request;
    context.validate_data()?;
    let original = state.original.as_ref().ok_or_else(refused)?;
    let terminal = state.terminal.as_ref().ok_or_else(refused)?;
    let response = state.decoded.as_deref().ok_or_else(refused)?;
    let Some(MethodResult::Capture(result)) = response.result.as_ref() else {
        return Err(refused());
    };
    if !matches!(
        &response.shape,
        crate::bodies::ResponseShape::Completed {
            operation_state: crate::bodies::OperationState::Completed,
            ..
        }
    ) || result.owner_state_refs.len() != 1
        || context.capture_request_id != state.request_id
        || context.capture_operation_id != state.operation_id
        || context.capture_request_hash != original.request_hash(RequestOrigin::Controller)?
        || context.capture_terminal_sequence != terminal.sequence
        || context.settled_capture_request
            != canonical::content_ref(&state.canonical, "application/json")?
        || context.native_snapshot_ref != result.capture_manifest
        || context.native_control_ref != result.owner_state_refs[0]
        || context.native_anchor_ref != result.unchanged_cut_receipt
    {
        return Err(refused());
    }
    original.matches_response(terminal)?;
    let value =
        serde_json::to_value(terminal).map_err(crucible_node_contract::ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if canonical::hash(PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN, &bytes)?
        != context.capture_terminal_hash
    {
        return Err(refused());
    }
    Ok(())
}
