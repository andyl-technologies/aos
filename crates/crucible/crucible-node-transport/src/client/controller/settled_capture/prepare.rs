//! Assigns the selected Capture and seals only its Source proof in place.

use super::*;
use crate::reference_packet::service::native_startup::original_restored_settled_capture_auxiliary_geometry_for_limits_data as auxiliary_geometry_data;

impl CnpController {
    /// Retains a selected administrative Capture before fallible assignment.
    ///
    /// The Source first admits the complete construction row under its genuine
    /// ticket/Window claim. The DTO and transport marker do not replace it.
    /// The existing Capture header keeps execution_owner absent and the actual
    /// separate administrative owner present; target identity is Source-signed.
    ///
    /// # Errors
    /// Refuses absent selected17 negotiation, unfinished prior originals, a used
    /// once slot, mismatched Capture data, expired cut or oversized assignment.
    /// Every initialized body/request/typed/DOM partial stays Controller-owned.
    pub fn reserve_original_restored_settled_capture(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        operation_id: Id,
        body: BeginRequest,
        request: PacketRestoredSettledCaptureRequest,
        maximum_auxiliary_originals: [usize; 2],
    ) -> Result<PreparedOriginalRestoredSettledCapture<'_>, ProviderError> {
        self.authenticate_restored_settled_capture_data(emitter)?;
        self.ensure_no_pending_original_ack_admit()?;
        self.ensure_no_pending_original_complete_restore()?;
        if self.original_restored_settled_capture.is_some() || self.original(&request_id).is_some()
        {
            return Err(refused());
        }
        self.original_restored_settled_capture = Some(AssignedRestoredSettledCapture {
            request_id,
            operation_id,
            body,
            request,
            prefix_frontier: None,
            auxiliary_uploads: [None, None],
            maximum_auxiliary_originals,
            arguments: None,
            unsigned_request: None,
            original: None,
            context: None,
            artifact: None,
            canonical: Vec::new(),
            cut: None,
            terminal: None,
            decoded: None,
            roots: Vec::new(),
            capture_frontier: None,
            confirmation: None,
            stage: Stage::Reserving,
        });
        let negotiated_limits = self.session.authority().limits();
        let state = self
            .original_restored_settled_capture
            .as_mut()
            .ok_or_else(refused)?;
        let originals = maximum_auxiliary_originals[0]
            .checked_add(maximum_auxiliary_originals[1])
            .and_then(|value| value.checked_add(2))
            .and_then(|value| {
                value.checked_add(
                    self.custody
                        .originals_by_origin(RequestOrigin::Controller)
                        .count(),
                )
            })
            .ok_or_else(refused)?;
        if maximum_auxiliary_originals.iter().any(|value| *value < 2)
            || originals > self.custody.maximum_requests()
        {
            return Err(refused());
        }
        let geometry = auxiliary_geometry_data(
            &negotiated_limits,
            &state.request.history_prefix,
            &state.request.runtime_object,
            maximum_auxiliary_originals[0]
                .checked_add(maximum_auxiliary_originals[1])
                .and_then(|value| value.checked_add(2))
                .ok_or_else(refused)?,
        )?;
        if geometry.maximum_auxiliary_originals_data() != maximum_auxiliary_originals {
            return Err(refused());
        }
        state.request.validate_data()?;
        if state.body.kind != BeginKind::Capture || !state.body.extensions.is_empty() {
            return Err(refused());
        }
        state.body.validate()?;
        let BeginArguments::Capture(arguments) = state.body.decoded_arguments()? else {
            return Err(refused());
        };
        state.arguments = Some(arguments);
        if state.arguments.as_ref() != Some(&state.request.capture)
            || state.request.scope.target.node != self.route.node
            || state.request.scope.target.owner != self.route.execution_owner
        {
            return Err(refused());
        }
        let prefix = self.session.fresh_restore_query_sequence()?;
        state.prefix_frontier = Some(prefix);
        if state.request.history_next_sequence != prefix
            || state.request.capture_operation != state.operation_id
        {
            return Err(refused());
        }
        state.stage = Stage::Reserved;
        Ok(PreparedOriginalRestoredSettledCapture { controller: self })
    }
}

impl PreparedOriginalRestoredSettledCapture<'_> {
    /// Retains the artifact, then inserts only its proof in the same original.
    ///
    /// # Errors
    /// Refuses a wrong phase/request, expired cut, changed assigned digest/context
    /// or excessive frame. Failed sealing is sticky and cannot replace the proof.
    pub fn seal_data(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        artifact: PacketRestoredSettledCaptureArtifact,
    ) -> Result<(), ProviderError> {
        self.controller
            .authenticate_restored_settled_capture_data(emitter)?;
        self.original_data()?;
        let maximum = self.controller.maximum_frame()?;
        let state = self
            .controller
            .original_restored_settled_capture
            .as_mut()
            .ok_or_else(refused)?;
        if state.stage != Stage::Unsigned || state.artifact.is_some() {
            return Err(refused());
        }
        state.stage = Stage::Sealing;
        state.artifact = Some(artifact);
        let artifact = state.artifact.as_ref().ok_or_else(refused)?;
        artifact.validate_data()?;
        if artifact.request != state.request {
            return Err(refused());
        }
        let assigned = restored_settled_capture_assigned_request_digest_data(
            state.original.as_ref().ok_or_else(refused)?,
            maximum,
        )?;
        state.context = Some(PacketRestoredSettledCaptureContext {
            schema: restored_settled_capture_context_schema_data().into(),
            request: state.request.clone(),
            assigned_request: crucible_node_format::Bytes::new(assigned.to_vec()),
        });
        let context = state.context.as_ref().ok_or_else(refused)?;
        if restored_settled_capture_context_digest_data(context)?.as_slice()
            != artifact.proof.context_digest.as_slice()
        {
            return Err(refused());
        }
        let original = state.original.as_mut().ok_or_else(refused)?;
        let extension = original
            .extensions
            .get_mut(RESTORED_SETTLED_CAPTURE_FEATURE)
            .and_then(Value::as_object_mut)
            .ok_or_else(refused)?;
        if extension.len() != 1 || !extension.contains_key("request") {
            return Err(refused());
        }
        extension.insert(
            "proof".into(),
            serde_json::to_value(&artifact.proof)
                .map_err(crucible_node_format::ContractError::from)?,
        );
        crate::connection::serialized_credit(original, maximum)?;
        let value =
            serde_json::to_value(&*original).map_err(crucible_node_format::ContractError::from)?;
        state.canonical = canonical::canonical_json(&value)?;
        if state.canonical.len() > maximum {
            return Err(refused());
        }
        state.stage = Stage::Sealed;
        Ok(())
    }
}

impl CnpController {
    /// Borrows the actual pre-auxiliary next sequence without creating an owner.
    ///
    /// The Source freezes its history prefix at this same value, then reserves
    /// the Capture owner before its two distinct scoped uploads. Reservation
    /// compares the value again; equality supplies no ticket or allocation row.
    ///
    /// # Errors
    /// Refuses another emitter, pending original or missing selected17 profile.
    pub fn original_restored_settled_capture_history_next_sequence_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<U64, ProviderError> {
        self.authenticate_restored_settled_capture_data(emitter)?;
        self.ensure_no_pending_original_complete_restore()?;
        self.session.fresh_restore_query_sequence()
    }
}

impl PreparedOriginalRestoredSettledCapture<'_> {
    /// Borrows the exact prefix frontier retained before any auxiliary original.
    ///
    /// # Errors
    /// Refuses an incomplete initial reservation. No clock coordinate is exposed.
    pub fn original_history_next_sequence_data(&self) -> Result<U64, ProviderError> {
        self.controller
            .original_restored_settled_capture
            .as_ref()
            .and_then(|state| state.prefix_frontier)
            .ok_or_else(refused)
    }

    /// Assigns Capture only after both dedicated ordinal transfers completed.
    ///
    /// Its new original cut starts here once; neither an upload cut nor the
    /// frozen pre-auxiliary prefix frontier is replaced or renewed.
    ///
    /// # Errors
    /// Refuses partial uploads, another actor/profile, repeated assignment,
    /// oversized frame or invalid complete original. All partials remain retained.
    pub fn assign_data(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        let controller = &mut *self.controller;
        controller.authenticate_restored_settled_capture_data(emitter)?;
        let maximum = controller.maximum_frame()?;
        let state = controller
            .original_restored_settled_capture
            .as_mut()
            .ok_or_else(refused)?;
        if state.stage != Stage::Reserved || !upload::both_complete(state) {
            return Err(refused());
        }
        state.stage = Stage::Assigning;
        let (sequence, cut) = controller
            .session
            .begin_original_ack_admit(controller.budget)?;
        state.cut = Some(cut);
        state.unsigned_request = Some(
            serde_json::to_value(&state.request)
                .map_err(crucible_node_format::ContractError::from)?,
        );
        let mut unsigned = serde_json::Map::new();
        unsigned.insert(
            "request".into(),
            state.unsigned_request.as_ref().ok_or_else(refused)?.clone(),
        );
        let mut extensions = Extensions::new();
        extensions.insert(
            RESTORED_SETTLED_CAPTURE_FEATURE.into(),
            Value::Object(unsigned),
        );
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
                request_id: &state.request_id,
                operation_id: &operation,
                sequence: U64::new(u64::MAX),
                method: Method::Begin,
                body: &state.body,
                extensions: &extensions,
            },
            maximum,
        )?;
        let Value::Object(body) =
            serde_json::to_value(&state.body).map_err(crucible_node_format::ContractError::from)?
        else {
            return Err(refused());
        };
        state.original = Some(Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(session)),
            incarnation_id: Nullable(Some(incarnation)),
            node_id: Nullable(node),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(Some(state.request.capture_owner.clone())),
            request_id: Nullable(Some(state.request_id.clone())),
            operation_id: Nullable(operation),
            sequence,
            method: Method::Begin,
            body,
            extensions,
        });
        restored_settled_capture_assigned_request_digest_data(
            state.original.as_ref().ok_or_else(refused)?,
            maximum,
        )?;
        controller
            .session
            .authenticate_original_ack_admit_cut(sequence, cut)?;
        state.stage = Stage::Unsigned;
        Ok(())
    }
}
