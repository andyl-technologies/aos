//! Retains one separately assigned restored Observe and all failed partials.

use super::*;
use crate::reference_packet::service::complete_restore::{activation::*, restoration_observe::*};
use serde::Deserialize;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ObservationState {
    Preparing,
    Unsigned,
    Sealing,
    Sealed,
    Publishing,
    Complete,
}

pub(super) struct AssignedOriginalInstalledRestorationObservation {
    body: ObserveRequest,
    request: PacketRestorationObservationRequest,
    unsigned_request: Option<Value>,
    original: Option<Envelope>,
    bytes: Vec<u8>,
    literal_slot: Option<usize>,
    cut: crate::operational_time::OperationalDeadline,
    state: ObservationState,
    response: Option<Envelope>,
    decoded: Option<ResponseBody>,
    completed_frontier: Option<U64>,
}

/// Borrows one actual assigned Observe without renewing its ID, sequence or cut.
#[must_use = "retain the same Controller and sticky partial through refusal"]
pub struct PreparedOriginalInstalledRestorationObservation<'a> {
    controller: &'a mut CnpController,
}

/// Borrows the actual completed observation pair and its retained typed body.
pub struct CompletedOriginalInstalledRestorationObservation<'a> {
    original: &'a Envelope,
    response: &'a Envelope,
    decoded: &'a ResponseBody,
    completed_frontier: U64,
    request: &'a PacketRestorationObservationRequest,
    body: &'a ObserveRequest,
}

impl CompletedOriginalInstalledRestorationObservation<'_> {
    /// Borrows the actual signed assigned original.
    pub fn original(&self) -> &Envelope {
        self.original
    }

    /// Borrows its actual correlated terminal response.
    pub fn response(&self) -> &Envelope {
        self.response
    }

    /// Borrows the actual retained typed terminal before additional Source copies.
    pub fn response_body_data(&self) -> &ResponseBody {
        self.decoded
    }

    /// Returns the saved SDK frontier after every promised proof was received.
    ///
    /// Later traffic cannot renew this immutable historical completion cut.
    pub const fn completed_frontier_data(&self) -> U64 {
        self.completed_frontier
    }
}

impl CnpController {
    /// Borrows the same installed selection through its defining session checks.
    ///
    /// This internal DATA loan does not expose the session, clone selection
    /// owners or issue an observation claim or request.
    ///
    /// # Errors
    /// Refuses another actor, missing or replaced native codec, or revoked
    /// original negotiation through the unchanged session selection validator.
    pub(crate) fn original_installed_restoration_observation_selection_data(
        &self,
    ) -> Result<&crate::reference_packet::control::PacketControlSelection, ProviderError> {
        self.session.fresh_restore_query_selection()
    }

    pub(super) fn ensure_no_pending_original_installed_restoration_observation(
        &self,
    ) -> Result<(), ProviderError> {
        if self
            .original_installed_restoration_observation
            .as_ref()
            .is_some_and(|state| state.state != ObservationState::Complete)
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) const fn original_installed_restoration_observation_owner_header_bytes_data() -> usize
    {
        std::mem::size_of::<AssignedOriginalInstalledRestorationObservation>()
    }

    /// Names actual SDK marker, owner, body and borrowed result headers.
    pub fn original_installed_restoration_observation_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<AssignedOriginalInstalledRestorationObservation>()
            + size_of::<Option<AssignedOriginalInstalledRestorationObservation>>()
            + size_of::<Option<&AssignedOriginalInstalledRestorationObservation>>()
            + size_of::<Option<&mut AssignedOriginalInstalledRestorationObservation>>()
            + size_of::<PreparedOriginalInstalledRestorationObservation<'static>>()
            + size_of::<
                Result<PreparedOriginalInstalledRestorationObservation<'static>, ProviderError>,
            >()
            + size_of::<CompletedOriginalInstalledRestorationObservation<'static>>()
            + size_of::<
                Result<CompletedOriginalInstalledRestorationObservation<'static>, ProviderError>,
            >()
            + size_of::<PacketRestorationActivationRequest>()
            + size_of::<Result<PacketRestorationActivationRequest, serde_json::Error>>()
            + size_of::<Result<ResponseBody, ProviderError>>()
            + size_of::<Result<RequestBody, ProviderError>>()
            + size_of::<Result<ContentRef, crucible_node_contract::ContractError>>()
            + size_of::<CompletedOriginalInstalledRestorationActivation<'static>>()
            + size_of::<
                Result<CompletedOriginalInstalledRestorationActivation<'static>, ProviderError>,
            >()
            + size_of::<CompletedOriginalCompleteRestoreTransfer<'static>>()
            + size_of::<Result<CompletedOriginalCompleteRestoreTransfer<'static>, ProviderError>>()
            + size_of::<Result<&AssignedOriginalInstalledRestorationObservation, ProviderError>>()
            + size_of::<Result<&mut AssignedOriginalInstalledRestorationObservation, ProviderError>>(
            )
            + size_of::<Result<&Envelope, ProviderError>>()
            + size_of::<Result<&ResponseBody, ProviderError>>()
            + size_of::<Result<&ObserveRequest, ProviderError>>()
            + size_of::<Option<&ObserveRequest>>()
            + size_of::<Result<&mut serde_json::Map<String, Value>, ProviderError>>()
            + size_of::<Result<&Value, ProviderError>>()
            + size_of::<ObservationState>()
            + size_of::<Option<U64>>()
            + size_of::<&ContentRef>()
            + size_of::<&[ContentRef]>()
            + size_of::<Option<&MethodResult>>()
            + size_of::<Option<&ObserveResult>>()
            + size_of::<&crucible_node_contract::ObservationBatch>()
            + size_of::<crate::bodies::RequestBody>()
            + size_of::<ResponseBody>()
            + size_of::<Envelope>()
            + size_of::<crate::reference_packet::control::PacketNative5UnderlyingRecord>()
            + size_of::<
                Result<
                    crate::reference_packet::control::PacketNative5UnderlyingRecord,
                    ProviderError,
                >,
            >()
            + size_of::<Result<ContentRef, ProviderError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<&Envelope>()
            + size_of::<&ResponseBody>()
            + size_of::<[(&ContentRef, &Envelope); 2]>()
            + size_of::<std::array::IntoIter<(&ContentRef, &Envelope), 2>>()
            + size_of::<Option<&Envelope>>()
            + size_of::<Option<&mut Envelope>>()
            + size_of::<Result<&mut Envelope, ProviderError>>()
            + size_of::<Option<&ResponseBody>>()
            + size_of::<Option<&mut serde_json::Map<String, Value>>>()
            + ClientSession::original_installed_restoration_observation_counter_scratch_data()
            + crate::connection::Connection::<crate::client::DeadlineStream>::original_assigned_installed_restoration_observation_counter_scratch_data()
            + size_of::<&crate::reference_packet::control::PacketControlSelection>()
            + size_of::<Result<&crate::reference_packet::control::PacketControlSelection, ProviderError>>()
            + restoration_observe_protocol_counter_scratch_data()
            + receive_storage::counter_scratch_data()
    }

    /// Assigns one observation only after the actual complete World pair.
    ///
    /// Source separately owns the genuine once Core claim and admitted copies.
    /// This SDK marker neither authenticates the MAC nor permits native effects.
    ///
    /// # Errors
    /// Refuses missing full negotiation, another actual Controller/target/row,
    /// incomplete Commit or World, changed actual pair, a reused ID/attempt,
    /// exhausted finite frame/journal banks or failed canonical construction.
    pub fn prepare_original_installed_restoration_observation<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        request: PacketRestorationObservationRequest,
        admitted: &OriginalInstalledRestorationObservationConstructionData,
    ) -> Result<PreparedOriginalInstalledRestorationObservation<'a>, ProviderError> {
        emitter.authenticate_original(self)?;
        self.ensure_no_pending_original_ack_admit()?;
        self.ensure_no_pending_original_complete_restore()?;
        admitted.authenticate_controller_data(std::rc::Rc::as_ptr(&self.protocol_owner).cast())?;
        if admitted.native_allocation_data() != request.native_allocation {
            return Err(refused());
        }
        request.validate_data()?;
        let selection = self.session.fresh_restore_query_selection()?;
        authenticate_restoration_observe_selection_data(selection, self.authority())?;
        self.original_installed_restoration_activation_target_binding_data()?
            .authenticate_scope_data(&request.scope)?;
        if self.original_installed_restoration_observation.is_some()
            || self.original(&request_id).is_some()
        {
            return Err(refused());
        }
        self.original_completed_complete_restore_transfer(
            emitter,
            crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase::Commit
        )?;
        self.original_completed_installed_restoration_activation(
            emitter,
            PacketRestorationActivationPhase::WorldActivate,
        )?;
        let maximum = self.maximum_frame()?;
        self.session
            .ensure_original_observation_receiver_idle_data()?;
        let (sequence, cut) = self.session.begin_original_ack_admit(self.budget)?;
        self.original_installed_restoration_observation =
            Some(AssignedOriginalInstalledRestorationObservation {
                body: ObserveRequest {
                    binding_hash: request.scope.target.binding_hash.clone(),
                    owner_generation: request.scope.target.owner_generation,
                    after_observation_sequence: U64::new(0),
                    maximum_items: U64::new(1),
                    extensions: Extensions::new(),
                },
                request,
                unsigned_request: None,
                original: None,
                bytes: Vec::new(),
                literal_slot: None,
                cut,
                state: ObservationState::Preparing,
                response: None,
                decoded: None,
                completed_frontier: None,
            });
        // Canonical pair checks can fail. Their actual request and cut already
        // reside in the sticky owner, so no later call can silently renew them.
        self.authenticate_observation_world_pair(emitter)?;
        let state = self
            .original_installed_restoration_observation
            .as_mut()
            .ok_or_else(refused)?;
        state.request.authenticate_body_data(&state.body)?;
        state.unsigned_request = Some(
            serde_json::to_value(&state.request)
                .map_err(crucible_node_contract::ContractError::from)?,
        );
        let Value::Object(body) = serde_json::to_value(&state.body)
            .map_err(crucible_node_contract::ContractError::from)?
        else {
            return Err(refused());
        };
        let mut unsigned = serde_json::Map::new();
        unsigned.insert(
            "request".into(),
            state.unsigned_request.take().ok_or_else(refused)?,
        );
        let mut extensions = Extensions::new();
        extensions.insert(
            PACKET_RESTORATION_OBSERVE_FEATURE.into(),
            Value::Object(unsigned),
        );
        state.original = Some(Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(self.session.authority().session_id().clone())),
            incarnation_id: Nullable(Some(self.session.authority().incarnation_id().clone())),
            node_id: Nullable(Some(self.route.node.clone())),
            execution_owner_id: Nullable(Some(self.route.execution_owner.clone())),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: Nullable(Some(request_id)),
            sequence,
            method: Method::Observe,
            body,
            extensions,
        });
        let original = state.original.as_ref().ok_or_else(refused)?;
        let final_maximum = crate::connection::serialized_credit(original, maximum)?
            .checked_add(maximum_restoration_observe_proof_encoded_bytes_data()?)
            .and_then(|n| n.checked_add(9))
            .ok_or_else(credit)?;
        if final_maximum > maximum {
            return Err(credit());
        }
        state
            .bytes
            .try_reserve_exact(final_maximum)
            .map_err(|_| credit())?;
        self.session
            .reserve_original_installed_restoration_observation(
                original,
                final_maximum,
                &mut state.literal_slot,
            )?;
        state.state = ObservationState::Unsigned;
        Ok(PreparedOriginalInstalledRestorationObservation { controller: self })
    }

    /// Checks suffix negotiation and the actual retained first Observe pair.
    ///
    /// This is SDK correspondence DATA. It does not prove that startup16 was
    /// written or received and does not authenticate a current advanced model.
    /// The Source wrapper supplies its genuine completed-wire and action claim
    /// under the same owning SourceRead; native ingress checks receipt separately.
    ///
    /// # Errors
    /// Refuses a foreign emitter, revoked codec, missing full negotiated suffix
    /// definitions, a fenced Controller, incomplete first Observe or a changed
    /// actual original/terminal in its immutable ClientCustody slot.
    pub fn authenticate_original_installed_restored_suffix_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self)?;
        self.protocol_owner.ensure_current()?;
        if self.fenced {
            return Err(refused());
        }
        let selection = self.session.fresh_restore_query_selection()?;
        crate::reference_packet::service::native_startup::authenticate_restoration_suffix_selection_data(
            selection,
            self.authority(),
        )?;

        let completed = self.original_completed_installed_restoration_observation(emitter)?;
        let id = completed
            .original()
            .request_id
            .0
            .as_ref()
            .ok_or_else(refused)?;
        let actual = self.original(id).ok_or_else(refused)?;
        if &actual.request != completed.original()
            || actual.response.as_ref() != Some(completed.response())
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Authenticates the saved first-observation frontier against this Session.
    ///
    /// This correspondence loan creates no action claim or native authority.
    ///
    /// # Errors
    /// Refuses another emitter/codec, incomplete or changed original custody,
    /// a changed saved completion frontier, or subsequent SDK traffic.
    pub fn authenticate_original_installed_restoration_observation_frontier_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        expected: U64,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_installed_restored_suffix_data(emitter)?;
        if self
            .original_completed_installed_restoration_observation(emitter)?
            .completed_frontier_data()
            != expected
            || self.session.fresh_restore_query_sequence()? != expected
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Borrows the actual retained closed body for an independent suffix quote.
    ///
    /// The first original remains historical ancestry. This loan creates no
    /// new request and grants no startup16 or per-action permission.
    ///
    /// # Errors
    /// Refuses foreign emitter/codec, incomplete first custody or a changed body.
    pub fn original_restored_suffix_observation_body_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<&ObserveRequest, ProviderError> {
        self.authenticate_original_installed_restored_suffix_data(emitter)?;
        let state = self
            .original_installed_restoration_observation
            .as_ref()
            .ok_or_else(refused)?;
        state.request.authenticate_body_data(&state.body)?;
        Ok(&state.body)
    }

    /// Checks a new actual suffix original against the immutable first scope.
    ///
    /// The first Observe remains historical ancestry. Its initial model cursor
    /// and inventory are deliberately not compared with this advancing record.
    /// Current frontier, Source-keyed chain and native proof freshness remain
    /// the independently admitted Source/Window consumer's obligations.
    ///
    /// # Errors
    /// Refuses another emitter/actual journal pair, changed restoration scope,
    /// held state, PID, request correlation or underlying native record.
    pub fn authenticate_original_restored_suffix_receipt_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        original: &Envelope,
        terminal: &Envelope,
        proof_original: &Envelope,
        record: &crate::reference_packet::service::complete_restore::PacketNativeRestoredRecord,
        underlying: &[u8],
    ) -> Result<crate::reference_packet::control::PacketNative5UnderlyingRecord, ProviderError>
    {
        self.authenticate_original_installed_restored_suffix_data(emitter)?;
        self.original_completed_installed_restoration_observation(emitter)?;
        let actual = original
            .request_id
            .0
            .as_ref()
            .and_then(|id| self.original(id))
            .ok_or_else(refused)?;
        if &actual.request != original || actual.response.as_ref() != Some(terminal) {
            return Err(refused());
        }
        original.matches_response(terminal)?;
        authenticate_suffix_proof_original_data(original, proof_original)?;
        let proof_id = proof_original.request_id.0.as_ref().ok_or_else(refused)?;
        if self.original(proof_id).map(|pair| &pair.request) != Some(proof_original) {
            return Err(refused());
        }
        let scope = &self
            .original_installed_restoration_observation
            .as_ref()
            .ok_or_else(refused)?
            .request
            .scope;
        record.validate_data()?;
        if record.captured_owner_state != scope.restoration.captured_owner_state
            || record.captured_journal != scope.restoration.captured_journal
            || record.mapping != scope.restoration.mapping
            || record.restore_commit != scope.restoration.commit_request
            || record.restore_response != scope.restoration.commit_response
            || record.context_digest != scope.restoration.context_digest
            || record.physical_gate_held
            || scope.target.native_pid.get() != u64::from(self.peer_pid())
        {
            return Err(refused());
        }
        record.native_receipt.verify_original_record_data(
            self.session.fresh_restore_query_selection()?,
            self.peer_pid(),
            proof_original,
            underlying,
        )
    }

    fn authenticate_observation_world_pair(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        let state = self
            .original_installed_restoration_observation
            .as_ref()
            .ok_or_else(refused)?;
        let world = self.original_completed_installed_restoration_activation(
            emitter,
            PacketRestorationActivationPhase::WorldActivate,
        )?;
        let unsigned = world
            .original()
            .extensions
            .get(PACKET_RESTORATION_ACTIVATION_FEATURE)
            .and_then(Value::as_object)
            .and_then(|value| value.get("request"))
            .ok_or_else(refused)?;
        let actual = PacketRestorationActivationRequest::deserialize(unsigned)
            .map_err(crucible_node_contract::ContractError::from)?;
        actual.validate_data()?;
        if actual.phase != PacketRestorationActivationPhase::WorldActivate
            || actual.scope != state.request.scope
        {
            return Err(refused());
        }
        for (expected, original) in [
            (&state.request.world_original, world.original()),
            (&state.request.world_terminal, world.response()),
        ] {
            crate::connection::serialized_credit(original, self.maximum_frame()?)?;
            let value = serde_json::to_value(original)
                .map_err(crucible_node_contract::ContractError::from)?;
            let encoded = canonical::canonical_json(&value)?;
            if &canonical::content_ref(&encoded, "application/json")? != expected {
                return Err(refused());
            }
        }
        Ok(())
    }

    /// Borrows the same genuine correlated terminal after SDK completion.
    ///
    /// # Errors
    /// Refuses another emitter, a partial attempt, absent typed body or a pair
    /// that no longer corresponds to the actual assigned signed original.
    pub fn original_completed_installed_restoration_observation(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<CompletedOriginalInstalledRestorationObservation<'_>, ProviderError> {
        emitter.authenticate_original(self)?;
        let state = self
            .original_installed_restoration_observation
            .as_ref()
            .ok_or_else(refused)?;
        if state.state != ObservationState::Complete {
            return Err(refused());
        }
        let original = state.original.as_ref().ok_or_else(refused)?;
        let response = state.response.as_ref().ok_or_else(refused)?;
        original.matches_response(response)?;
        Ok(CompletedOriginalInstalledRestorationObservation {
            original,
            response,
            decoded: state.decoded.as_ref().ok_or_else(refused)?,
            completed_frontier: state.completed_frontier.ok_or_else(refused)?,
            request: &state.request,
            body: &state.body,
        })
    }

    /// Verifies the actual current Observe record and its full underlying model.
    ///
    /// Source independently retains both decoded owners before its final fence,
    /// checks the actual scope/model correspondence and authenticates the MAC.
    ///
    /// # Errors
    /// Refuses a foreign/unfinished original, another native PID, changed full
    /// Commit/mapping/capture/context, held=true, or an altered underlying model.
    pub fn authenticate_original_installed_restoration_observation_evidence_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        record: &crate::reference_packet::service::complete_restore::PacketNativeRestoredRecord,
        underlying: &[u8],
    ) -> Result<crate::reference_packet::control::PacketNative5UnderlyingRecord, ProviderError>
    {
        let completed = self.original_completed_installed_restoration_observation(emitter)?;
        let state = self
            .original_installed_restoration_observation
            .as_ref()
            .ok_or_else(refused)?;
        let scope = &state.request.scope;
        record.validate_data()?;
        if record.captured_owner_state != scope.restoration.captured_owner_state
            || record.captured_journal != scope.restoration.captured_journal
            || record.mapping != scope.restoration.mapping
            || record.restore_commit != scope.restoration.commit_request
            || record.restore_response != scope.restoration.commit_response
            || record.context_digest != scope.restoration.context_digest
            || record.physical_gate_held
            || scope.target.native_pid.get() != u64::from(self.peer_pid())
        {
            return Err(refused());
        }
        let selection = self.session.fresh_restore_query_selection()?;
        authenticate_restoration_observe_selection_data(selection, self.authority())?;
        record.native_receipt.verify_original_record_data(
            selection,
            self.peer_pid(),
            completed.original(),
            underlying,
        )
    }
}

impl PreparedOriginalInstalledRestorationObservation<'_> {
    /// Borrows the same assigned original without changing its cut or sequence.
    ///
    /// # Errors
    /// Refuses a stale Controller, absent owner or expired unfinished cut.
    pub fn original(&self) -> Result<&Envelope, ProviderError> {
        self.controller.protocol_owner.ensure_current()?;
        let state = self
            .controller
            .original_installed_restoration_observation
            .as_ref()
            .ok_or_else(refused)?;
        let original = state.original.as_ref().ok_or_else(refused)?;
        if state.state != ObservationState::Complete {
            self.controller
                .session
                .authenticate_original_ack_admit_cut(original.sequence, state.cut)?;
        }
        Ok(original)
    }

    /// Inserts only the proof into the already assigned and retained request.
    ///
    /// # Errors
    /// Refuses a foreign emitter, repeated seal, changed request/digest or an
    /// oversized full final frame. Every original and partial remains retained.
    pub fn seal(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        artifact: PacketRestorationObservationArtifact,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self.controller)?;
        let maximum = self.controller.maximum_frame()?;
        let assigned = restoration_observe_assigned_request_digest(self.original()?, maximum)?;
        artifact.validate_data()?;
        let state = self
            .controller
            .original_installed_restoration_observation
            .as_mut()
            .ok_or_else(refused)?;
        if state.state != ObservationState::Unsigned || artifact.request != state.request {
            return Err(refused());
        }
        let context = PacketRestorationObservationContext {
            request: artifact.request.clone(),
            assigned_request: crucible_node_contract::Bytes::new(assigned.to_vec()),
        };
        if restoration_observe_context_digest_data(&context)?.as_slice()
            != artifact.proof.context_digest.as_slice()
        {
            return Err(refused());
        }
        state.state = ObservationState::Sealing;
        let original = state.original.as_mut().ok_or_else(refused)?;
        let unsigned = original
            .extensions
            .get_mut(PACKET_RESTORATION_OBSERVE_FEATURE)
            .and_then(Value::as_object_mut)
            .ok_or_else(refused)?;
        if unsigned.len() != 1 || !unsigned.contains_key("request") {
            return Err(refused());
        }
        unsigned.insert(
            "proof".into(),
            serde_json::to_value(artifact.proof)
                .map_err(crucible_node_contract::ContractError::from)?,
        );
        crate::connection::serialized_credit(original, maximum)?;
        self.controller.session.seal_original_ack_admit(
            &mut self.controller.custody,
            original,
            &mut state.bytes,
            state.literal_slot,
        )?;
        state.state = ObservationState::Sealed;
        Ok(())
    }

    /// Publishes that original and retains raw and typed terminals before return.
    ///
    /// # Errors
    /// Refuses another emitter/cut, nonsealed attempt, occupied caller output or
    /// protocol/decode failure. Source alone authenticates successful completion.
    pub fn publish_into(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self.controller)?;
        self.original()?;
        if completed.is_some() {
            return Err(refused());
        }
        let state = self
            .controller
            .original_installed_restoration_observation
            .as_mut()
            .ok_or_else(refused)?;
        if state.state != ObservationState::Sealed {
            return Err(refused());
        }
        state.state = ObservationState::Publishing;
        let original = state.original.as_ref().ok_or_else(refused)?;
        self.controller
            .session
            .publish_original_installed_restoration_observation(
                &mut self.controller.custody,
                original,
                &state.bytes,
                state.literal_slot,
                state.cut,
                &mut state.response,
                &mut state.decoded,
            )?;
        let response = state.response.as_ref().ok_or_else(refused)?;
        original.matches_response(response)?;
        *completed = Some(state.decoded.as_ref().ok_or_else(refused)?.clone());
        self.controller
            .complete_original_installed_observation_content_data()
    }

    /// Borrows the completed pair while retaining the exclusive Controller loan.
    ///
    /// # Errors
    /// Refuses another emitter or an incomplete/unmatched actual terminal.
    pub fn completed_original(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<CompletedOriginalInstalledRestorationObservation<'_>, ProviderError> {
        self.controller
            .original_completed_installed_restoration_observation(emitter)
    }
}

impl CnpController {
    // The endpoint sends the terminal before its dependency-ordered Blob suffix.
    // Keep the same raw/typed terminal and original cut while receiving that
    // suffix; observing a terminal alone cannot complete this SDK owner.
    fn complete_original_installed_observation_content_data(
        &mut self,
    ) -> Result<(), ProviderError> {
        self.session
            .ensure_original_observation_receiver_idle_data()?;
        let state = self
            .original_installed_restoration_observation
            .as_mut()
            .ok_or_else(refused)?;
        if state.state != ObservationState::Publishing
            || state.completed_frontier.is_some()
            || state.response.is_none()
        {
            return Err(refused());
        }
        let decoded = state.decoded.as_ref().ok_or_else(refused)?;
        if let Some(MethodResult::Observe(result)) = decoded.result.as_ref() {
            // The actual signed request admits exactly one complete observation.
            // Borrow its retained root directly: no replacement root vector or
            // independent allocation is introduced between terminal and proof.
            let [batch] = result.observations.as_slice() else {
                return Err(refused());
            };
            self.session.receive_content(
                &mut self.custody,
                std::slice::from_ref(&batch.measurement_ref),
                self.budget,
            )?;
        }
        state.completed_frontier = Some(self.session.fresh_restore_query_sequence()?);
        state.state = ObservationState::Complete;
        Ok(())
    }
}

impl AssignedOriginalInstalledRestorationObservation {
    pub(super) fn observe_owned_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            body,
            request,
            unsigned_request,
            original,
            bytes,
            literal_slot: _,
            cut: _,
            state,
            response,
            decoded,
            completed_frontier,
        } = self;
        match state {
            ObservationState::Preparing
            | ObservationState::Unsigned
            | ObservationState::Sealing
            | ObservationState::Sealed
            | ObservationState::Publishing
            | ObservationState::Complete => {}
        }
        // This closed walker visits actual independent typed owners, including
        // errors and unused byte capacity, without requiring a completed phase.
        use crate::reference_packet::service::complete_restore::restoration_observe::RetainedRestorationObservationData as Owned;
        Owned::Body(body).observe_owned_metadata_data(observer)?;
        request.observe_owned_metadata_data(observer)?;
        observer.observe(unsigned_request)?;
        observer.observe(original)?;
        observer.vector::<u8>(bytes.capacity())?;
        observer.observe(response)?;
        observer.observe(completed_frontier)?;
        if let Some(decoded) = decoded {
            Owned::Response(decoded).observe_owned_metadata_data(observer)?;
        }
        Ok(())
    }
}

fn authenticate_suffix_proof_original_data(
    original: &Envelope,
    proof_original: &Envelope,
) -> Result<(), ProviderError> {
    if original.method == Method::Poll {
        if proof_original.method != Method::Begin
            || original.operation_id.0.is_none()
            || original.operation_id != proof_original.operation_id
        {
            return Err(refused());
        }
    } else if original != proof_original {
        return Err(refused());
    }

    Ok(())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original installed restoration observation changed")
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("installed restoration observation original credit")
}

#[cfg(all(test, unix))]
mod pending_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn partial_observation_blocks_real_generic_route_before_frontier_change() {
        let (_handshake, session, _owner, _witness, _peer) =
            ClientSession::restoration_retained_fixture();
        let content = crate::client::ClientContent::new(1024 * 1024, 16, 4096).unwrap();
        let custody = ClientCustody::new(16, content).unwrap();
        let mut controller = CnpController::new(
            session,
            custody,
            ControllerRoute {
                node: Id::new("raw-census-node").unwrap(),
                execution_owner: Id::new("raw-census-owner").unwrap(),
            },
            Duration::from_secs(30),
        )
        .unwrap();
        // Actual owner slots exercise refusal only. Portable fixture DATA cannot
        // issue an observation claim, seal a native MAC or permit any send.
        let scope =
            crate::reference_packet::service::complete_restore::activation::tests::request()
                .unwrap()
                .scope;
        let request = PacketRestorationObservationRequest {
            schema: PACKET_RESTORATION_OBSERVE_FEATURE.into(),
            scope,
            world_original: canonical::content_ref(b"world-original-data", "application/json")
                .unwrap(),
            world_terminal: canonical::content_ref(b"world-terminal-data", "application/json")
                .unwrap(),
            maximum_items: U64::new(1),
            native_allocation: PacketRestorationActivationAllocationRow {
                retained_requested_bytes: U64::new(1),
                maximum_simultaneous_transient_bytes: U64::new(2),
                declared_counter_scratch_bytes: U64::new(3),
            },
        };
        let sequence = controller.session.fresh_restore_query_sequence().unwrap();
        let originals = controller.originals().count();
        for state in [
            ObservationState::Preparing,
            ObservationState::Unsigned,
            ObservationState::Sealing,
            ObservationState::Sealed,
            ObservationState::Publishing,
        ] {
            controller.original_installed_restoration_observation =
                Some(AssignedOriginalInstalledRestorationObservation {
                    body: ObserveRequest {
                        binding_hash: request.scope.target.binding_hash.clone(),
                        owner_generation: request.scope.target.owner_generation,
                        after_observation_sequence: U64::new(0),
                        maximum_items: U64::new(1),
                        extensions: Extensions::new(),
                    },
                    request: request.clone(),
                    unsigned_request: None,
                    original: None,
                    bytes: Vec::new(),
                    literal_slot: None,
                    cut: crate::operational_time::OperationalDeadline::after(Duration::from_secs(
                        30,
                    ))
                    .unwrap(),
                    state,
                    response: None,
                    decoded: None,
                    completed_frontier: None,
                });
            assert!(
                controller
                    .ensure_no_pending_original_complete_restore()
                    .is_err()
            );
            let id = Id::new("blocked-observation-peer").unwrap();
            // The precise pending refusal must precede even invalid baseline
            // DATA. Removing the real call barrier would instead return Frame.
            assert!(matches!(
                controller.call(id.clone(), None, Method::Observe, false, Value::Null),
                Err(ProviderError::Correlation(
                    "original installed restoration observation changed"
                ))
            ));
            assert_eq!(
                controller.session.fresh_restore_query_sequence().unwrap(),
                sequence
            );
            assert_eq!(controller.originals().count(), originals);
            assert!(controller.original(&id).is_none());
        }
        controller
            .original_installed_restoration_observation
            .as_mut()
            .unwrap()
            .state = ObservationState::Complete;
        // Only this pending barrier permits further checks; no completed pair,
        // Source evidence or native observation authority is manufactured.
        assert!(
            controller
                .ensure_no_pending_original_complete_restore()
                .is_ok()
        );
        assert_eq!(
            controller.session.fresh_restore_query_sequence().unwrap(),
            sequence
        );
        assert_eq!(controller.originals().count(), originals);
    }
}

#[cfg(test)]
mod suffix_data_tests {
    use super::*;

    #[test]
    fn suffix_poll_receipt_uses_its_actual_begin_original_not_the_poll() {
        let mut begin = crate::envelope::tests::request();
        begin.method = Method::Begin;
        begin.request_id = Nullable(Some(Id::new("suffix/begin").unwrap()));
        begin.operation_id = Nullable(Some(Id::new("suffix/operation").unwrap()));
        let mut poll = begin.clone();
        poll.method = Method::Poll;
        poll.request_id = Nullable(Some(Id::new("suffix/poll").unwrap()));
        poll.sequence = U64::new(19);

        assert!(authenticate_suffix_proof_original_data(&poll, &begin).is_ok());
        assert!(authenticate_suffix_proof_original_data(&poll, &poll).is_err());
        let mut foreign = begin.clone();
        foreign.operation_id = Nullable(Some(Id::new("suffix/foreign").unwrap()));
        assert!(authenticate_suffix_proof_original_data(&poll, &foreign).is_err());
        assert!(authenticate_suffix_proof_original_data(&begin, &poll).is_err());
        assert!(authenticate_suffix_proof_original_data(&begin, &begin).is_ok());
    }
}

impl AssignedOriginalInstalledRestorationObservation {
    pub(super) fn borrowed_settled_history_data(
        &self,
    ) -> Result<impl serde::Serialize + '_, ProviderError> {
        let Self {
            body,
            request,
            unsigned_request,
            original,
            bytes,
            literal_slot,
            cut: _,
            state,
            response,
            decoded,
            completed_frontier,
        } = self;
        let decoded = decoded
            .as_ref()
            .map(crate::retained_metadata::historical_response_body_data)
            .transpose()?;
        Ok((
            "source-private.sdk-first-observation-current/17",
            body,
            request,
            unsigned_request,
            original,
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(bytes),
            bytes.capacity(),
            literal_slot,
            match state {
                ObservationState::Preparing => "preparing",
                ObservationState::Unsigned => "unsigned",
                ObservationState::Sealing => "sealing",
                ObservationState::Sealed => "sealed",
                ObservationState::Publishing => "publishing",
                ObservationState::Complete => "complete",
            },
            response,
            decoded,
            "historical-nonrenewable-operational-cut",
            completed_frontier,
        ))
    }
}

fn settled_field_views<T>(
    _: impl FnOnce(&'static AssignedOriginalInstalledRestorationObservation) -> T,
) -> usize {
    std::mem::size_of::<T>()
}

impl AssignedOriginalInstalledRestorationObservation {
    pub(super) fn settled_history_counter_scratch_data() -> usize {
        settled_field_views(|value| {
            (
                value.borrowed_settled_history_data(),
                Some(value.borrowed_settled_history_data()),
                Some(value)
                    .map(|value| value.borrowed_settled_history_data())
                    .transpose(),
            )
        }) + settled_field_views(|value| {
            let AssignedOriginalInstalledRestorationObservation {
                body,
                request,
                unsigned_request,
                original,
                bytes,
                literal_slot,
                cut,
                state,
                response,
                decoded,
                completed_frontier,
            } = value;
            (
                body,
                request,
                unsigned_request,
                original,
                bytes,
                literal_slot,
                cut,
                state,
                response,
                decoded,
                completed_frontier,
            )
        }) + std::mem::size_of::<&Self>()
            + std::mem::size_of::<Option<&Self>>()
            + std::mem::size_of::<&mut crate::retained_metadata::MetadataObserver<'static>>()
            + std::mem::size_of::<Result<(), ProviderError>>()
    }
}

#[cfg(all(test, unix))]
#[path = "installed_observation/evidence_tests.rs"]
mod evidence_tests;

mod receive_storage;

#[path = "installed_observation/checkpoint_cache17.rs"]
mod checkpoint_cache17;
