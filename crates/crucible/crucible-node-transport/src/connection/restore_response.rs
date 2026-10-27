//! Assigns an actual native restoration response before its receipt MAC or I/O.
//!
//! The Connection retains the complete response, literal slot, immutable cut and
//! sticky phase. A loan can end without releasing those owners. Signing uses the
//! genuine private native prepare token and acknowledged input custody; callers
//! cannot substitute a predicted response sequence or an ordinary receipt DTO.

use super::*;
use crate::client::{DeadlineStream, ExchangeDeadline};
use crate::operational_time::OperationalDeadline;
use crate::reference_packet::service::complete_restore::{
    PacketNative5CompleteRestoreSelection,
    transfer::{
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES, PacketCompleteRestoreTransferPhase,
    },
};
use std::cell::RefCell;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Unsigned,
    Sealing,
    Sealed,
    Publishing,
    Complete,
}

pub(super) struct AssignedNativeRestoreResponse {
    original: Envelope,
    canonical: Vec<u8>,
    literal_slot: Option<usize>,
    request_sequence: crucible_node_format::U64,
    completed_proof: Option<super::restore_held_proof::CompletedHeldProof>,
    deadline: ExchangeDeadline,
    cut: OperationalDeadline,
    phase: Phase,
}

#[must_use = "the exact assigned native response remains in its Connection"]
pub(crate) struct PreparedOriginalNativeRestoreResponse<'a> {
    connection: &'a mut Connection<DeadlineStream>,
    phase: PacketCompleteRestoreTransferPhase,
}

fn index(phase: PacketCompleteRestoreTransferPhase) -> usize {
    match phase {
        PacketCompleteRestoreTransferPhase::Prepare => 0,
        PacketCompleteRestoreTransferPhase::Commit => 1,
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(super) fn original_unsigned_restore_response_slot(
        &self,
    ) -> Result<Option<usize>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        let mut slot = None;
        for owner in self.original_restore_responses.iter().flatten() {
            let state = owner.try_borrow().map_err(|_| borrowed())?;
            if state.phase == Phase::Unsigned {
                if slot.is_some()
                    || state.deadline.original_cut() != state.cut
                    || state.cut.remaining().is_none()
                {
                    return Err(refused());
                }
                slot = Some(state.literal_slot.ok_or_else(refused)?);
            } else if state.phase != Phase::Complete {
                return Err(refused());
            }
        }
        Ok(slot)
    }

    pub(super) fn ensure_no_pending_native_restore_response(&self) -> Result<(), ProviderError> {
        if self.original_restore_responses.iter().all(Option::is_none) {
            return Ok(());
        }
        self.protocol_owner.ensure_current()?;
        for owner in self.original_restore_responses.iter().flatten() {
            if owner.try_borrow().map_err(|_| borrowed())?.phase != Phase::Complete {
                return Err(refused());
            }
        }
        Ok(())
    }

    pub(crate) fn authenticate_original_assigned_restore_response(
        &self,
        request: &Envelope,
        response: &Envelope,
        phase: PacketCompleteRestoreTransferPhase,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let projection = self.original_selected_restore_transfer_projection_data(request)?;
        if projection.phase() != phase || self.role != EndpointRole::Provider {
            return Err(refused());
        }
        let owner = self.original_restore_responses[index(phase)]
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| borrowed())?;
        if owner.phase != Phase::Unsigned
            || owner.original != *response
            || owner.request_sequence != request.sequence
            || owner.deadline.original_cut() != owner.cut
            || owner.cut.remaining().is_none()
            || self.original_native_restore_response_sequence(
                request,
                owner.completed_proof.as_ref(),
            )? != response.sequence
        {
            return Err(refused());
        }
        request.matches_response(response)?;
        let slot = owner.literal_slot.ok_or_else(refused)?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| borrowed())?;
        let frame = bank.frame(slot).ok_or_else(refused)?;
        if frame.direction != crate::transport::original_frames::FrameDirection::Outgoing
            || !frame.bytes.is_empty()
            || frame.transferred != 0
            || frame.complete
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl<S: ProviderStream> Connection<S> {
    fn original_native_restore_response_sequence(
        &self,
        request: &Envelope,
        proof: Option<&super::restore_held_proof::CompletedHeldProof>,
    ) -> Result<crucible_node_format::U64, ProviderError> {
        match proof {
            Some(proof) => {
                proof.authenticate_retained(self, request)?;
                self.guard
                    .original_restore_response_after_proof_sequence(request, proof)
            }
            None => self.guard.original_restore_response_sequence(request),
        }
    }
}

impl Connection<DeadlineStream> {
    pub(crate) fn prepare_original_complete_restore_response(
        &mut self,
        request: &Envelope,
        response: &ResponseBody,
        phase: PacketCompleteRestoreTransferPhase,
    ) -> Result<PreparedOriginalNativeRestoreResponse<'_>, ProviderError> {
        if phase != PacketCompleteRestoreTransferPhase::Prepare {
            return Err(refused());
        }
        self.prepare_original_native_restore_response(request, response, phase, None)
    }

    pub(crate) fn prepare_original_complete_restore_commit_response(
        &mut self,
        request: &Envelope,
        held: &crate::reference_packet::service::ack_emitter::VerifiedCompleteRestorationHeld,
        completed_proof: &ExchangeRecord,
    ) -> Result<PreparedOriginalNativeRestoreResponse<'_>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        held.authenticate_current(self, request)?;
        let proof = {
            let evidence = held.original_gate_evidence(self, request)?;
            super::restore_held_proof::CompletedHeldProof::authenticate_exchange(
                self,
                request,
                completed_proof,
                &evidence.0,
                &evidence.1,
            )?
        };
        let result = held.original_result_data(self, request)?;
        let serde_json::Value::Object(value) =
            serde_json::to_value(&result).map_err(crucible_node_format::ContractError::from)?
        else {
            return Err(refused());
        };
        let response = ResponseBody {
            shape: crate::bodies::ResponseShape::Completed {
                operation_state: crate::bodies::OperationState::Completed,
                result: value,
                extensions: crucible_node_format::Extensions::new(),
            },
            result: Some(crate::bodies::MethodResult::PrepareRestore(result)),
        };
        self.prepare_original_native_restore_response(
            request,
            &response,
            PacketCompleteRestoreTransferPhase::Commit,
            Some(proof),
        )
    }

    fn prepare_original_native_restore_response(
        &mut self,
        request: &Envelope,
        response: &ResponseBody,
        phase: PacketCompleteRestoreTransferPhase,
        completed_proof: Option<super::restore_held_proof::CompletedHeldProof>,
    ) -> Result<PreparedOriginalNativeRestoreResponse<'_>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.check_authority()?;
        self.authenticate_native5_source_codec()?;
        self.ensure_no_pending_native_restore_response()?;
        if self.role != EndpointRole::Provider
            || self.original_native5_complete_restore_selection()?
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || self.original_restore_responses[index(phase)].is_some()
        {
            return Err(refused());
        }
        if phase == PacketCompleteRestoreTransferPhase::Prepare {
            self.acknowledge_original_complete_restore_input_custody()?;
        }
        // Commit is reachable only through the genuine Held producer and its
        // completed proof witness. The sealed native owner has already moved
        // from input custody into that installed mapping; reacknowledging the
        // old input slot would require ownership that was deliberately moved.

        let projection = self.original_selected_restore_transfer_projection_data(request)?;
        if projection.phase() != phase
            || !matches!(
                projection,
                CompleteRestoreTransferProjection::Request { .. }
            )
        {
            return Err(refused());
        }
        if (phase == PacketCompleteRestoreTransferPhase::Commit) != completed_proof.is_some() {
            return Err(refused());
        }
        let sequence =
            self.original_native_restore_response_sequence(request, completed_proof.as_ref())?;
        if !matches!(
            response.shape,
            crate::bodies::ResponseShape::Completed {
                operation_state: crate::bodies::OperationState::Completed,
                ..
            }
        ) || !matches!(
            response.result,
            Some(crate::bodies::MethodResult::PrepareRestore(_))
        ) {
            return Err(refused());
        }
        let Some(crate::bodies::MethodResult::PrepareRestore(result)) = &response.result else {
            return Err(refused());
        };
        if result.staged_owner_ids.len() != 1 {
            return Err(refused());
        }
        let maximum = allowance(self.authority.limits().frame_bytes.get())?;
        serialized_credit(&response.shape, 4096)?;
        let body = serde_json::to_value(&response.shape)
            .map_err(crucible_node_format::ContractError::from)?;
        let serde_json::Value::Object(body) = body else {
            return Err(refused());
        };
        let actual_request = crate::bodies::decode_request(request.method, &request.body)?;
        if crate::bodies::decode_response(&actual_request, &body)? != *response {
            return Err(refused());
        }
        if body
            .get("extensions")
            .and_then(serde_json::Value::as_object)
            .is_none_or(|v| !v.is_empty())
        {
            return Err(refused());
        }
        let deadline = self
            .reader
            .stream_ref()
            .retain_original_operation_deadline()?;
        let cut = deadline.original_cut();
        let original = Envelope {
            protocol: request.protocol.clone(),
            message: MessageKind::Response,
            session_id: request.session_id.clone(),
            incarnation_id: request.incarnation_id.clone(),
            node_id: request.node_id.clone(),
            execution_owner_id: request.execution_owner_id.clone(),
            capture_owner_id: request.capture_owner_id.clone(),
            request_id: request.request_id.clone(),
            operation_id: request.operation_id.clone(),
            sequence,
            method: request.method,
            body,
            extensions: crucible_node_format::Extensions::new(),
        };
        request.matches_response(&original)?;
        let final_maximum = serialized_credit(&original, maximum)?
            .checked_add(phase.receipt_extension().len() + 3)
            .and_then(|n| n.checked_add(MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES))
            .filter(|n| *n <= maximum)
            .ok_or_else(credit)?;
        self.original_restore_responses[index(phase)] =
            Some(Rc::new(RefCell::new(AssignedNativeRestoreResponse {
                original,
                canonical: Vec::new(),
                literal_slot: None,
                request_sequence: request.sequence,
                completed_proof,
                deadline,
                cut,
                phase: Phase::Unsigned,
            })));
        let owner = self.original_restore_responses[index(phase)]
            .as_ref()
            .ok_or_else(refused)?;
        let mut state = owner.try_borrow_mut().map_err(|_| borrowed())?;
        state
            .canonical
            .try_reserve_exact(final_maximum)
            .map_err(|_| credit())?;
        let mut bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow_mut()
            .map_err(|_| borrowed())?;
        if !bank.complete() {
            return Err(refused());
        }
        let slot = bank.begin(
            crate::transport::original_frames::FrameDirection::Outgoing,
            final_maximum.checked_add(4).ok_or_else(credit)?,
        )?;
        state.literal_slot = Some(slot);
        bank.retain_request(
            slot,
            state.original.request_id.0.as_ref().ok_or_else(refused)?,
        )?;
        drop(bank);
        drop(state);
        Ok(PreparedOriginalNativeRestoreResponse {
            connection: self,
            phase,
        })
    }
}

impl PreparedOriginalNativeRestoreResponse<'_> {
    pub(crate) fn original(&self) -> Result<std::cell::Ref<'_, Envelope>, ProviderError> {
        self.connection.protocol_owner.ensure_current()?;
        let owner = self.connection.original_restore_responses[index(self.phase)]
            .as_ref()
            .ok_or_else(refused)?;
        let state = owner.try_borrow().map_err(|_| borrowed())?;
        if state.deadline.original_cut() != state.cut || state.cut.remaining().is_none() {
            return Err(refused());
        }
        Ok(std::cell::Ref::map(state, |state| &state.original))
    }

    pub(crate) fn seal_original_prepare_receipt(&mut self) -> Result<(), ProviderError> {
        self.connection.protocol_owner.ensure_current()?;
        if self.phase != PacketCompleteRestoreTransferPhase::Prepare {
            return Err(refused());
        }
        let receipt = {
            let response = self.original()?;
            let installed = self
                .connection
                .original_restore_inputs
                .as_ref()
                .ok_or_else(refused)?;
            installed
                .token
                .prepare_receipt_data(self.connection, &response)?
        };
        receipt.validate_data()?;
        self.seal_original_receipt(receipt)
    }

    pub(crate) fn seal_original_commit_receipt(
        &mut self,
        held: &crate::reference_packet::service::ack_emitter::VerifiedCompleteRestorationHeld,
    ) -> Result<(), ProviderError> {
        self.connection.protocol_owner.ensure_current()?;
        if self.phase != PacketCompleteRestoreTransferPhase::Commit {
            return Err(refused());
        }
        let receipt = {
            let response = self.original()?;
            held.prepare_receipt_data(self.connection, &response)?
        };
        receipt.validate_data()?;
        self.seal_original_receipt(receipt)
    }

    fn seal_original_receipt(
        &mut self,
        receipt: impl serde::Serialize,
    ) -> Result<(), ProviderError> {
        let owner = Rc::clone(
            self.connection.original_restore_responses[index(self.phase)]
                .as_ref()
                .ok_or_else(refused)?,
        );
        let mut state = owner.try_borrow_mut().map_err(|_| borrowed())?;
        if state.phase != Phase::Unsigned || !state.original.extensions.is_empty() {
            return Err(refused());
        }
        state.phase = Phase::Sealing;
        let value =
            serde_json::to_value(receipt).map_err(crucible_node_format::ContractError::from)?;
        state
            .original
            .extensions
            .insert(self.phase.receipt_extension().into(), value);
        let AssignedNativeRestoreResponse {
            original,
            canonical,
            literal_slot,
            ..
        } = &mut *state;
        self.connection
            .seal_original_assigned_ack_admit(original, canonical, *literal_slot)?;
        state.phase = Phase::Sealed;
        Ok(())
    }

    pub(crate) fn publish(&mut self) -> Result<(), ProviderError> {
        self.connection.protocol_owner.ensure_current()?;
        self.connection.check_authority()?;
        let owner = Rc::clone(
            self.connection.original_restore_responses[index(self.phase)]
                .as_ref()
                .ok_or_else(refused)?,
        );
        let mut state = owner.try_borrow_mut().map_err(|_| borrowed())?;
        if state.phase != Phase::Sealed
            || state.deadline.original_cut() != state.cut
            || state.cut.remaining().is_none()
        {
            return Err(refused());
        }
        state.phase = Phase::Publishing;
        let result = self
            .connection
            .publish_original_send(&state.canonical, state.literal_slot);
        if let Err(error) = result {
            self.connection.contain(ConnectionFailure::Write);
            return Err(error);
        }
        self.connection
            .guard
            .confirm_response_sent(&state.original)?;
        state.phase = Phase::Complete;
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("assigned native restore response changed")
}
fn borrowed() -> ProviderError {
    ProviderError::Conflict("assigned native restore response borrowed")
}
fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("assigned native restore response banks")
}

pub(super) fn original_restore_response_owner_layout() -> usize {
    std::mem::size_of::<std::cell::RefCell<AssignedNativeRestoreResponse>>()
        + 2 * std::mem::size_of::<usize>()
        + std::mem::align_of::<std::cell::RefCell<AssignedNativeRestoreResponse>>()
        - 1
}

impl<S: ProviderStream> Connection<S> {
    /// Authenticates the complete actual Prepare chain retained on this connection.
    ///
    /// The raw request must equal the Source-attested full canonical envelope
    /// digest. Noncanonical incoming spellings conservatively refuse. The actual
    /// completed response is checked against its original sent literal slot;
    /// historical digests never substitute for these current owning associations.
    pub(crate) fn authenticate_original_complete_restore_prepare_data(
        &self,
        commit: &crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreCommitRequest,
    ) -> Result<(), ProviderError> {
        use super::restore_held_proof::{borrowed_field, borrowed_u64_field};
        use crate::protocol_snapshot::owned11::original_owned11_plain_string as plain_string;
        use crate::reference_packet::service::complete_restore::transfer::*;
        use crate::transport::original_frames::FrameDirection;

        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider || self.fenced {
            return Err(refused());
        }
        commit.validate_data()?;
        let installed = self.original_restore_inputs.as_ref().ok_or_else(refused)?;
        installed.token.authenticate_current(self)?;
        let request = installed.token.request(self)?;
        installed
            .custody
            .try_borrow()
            .map_err(|_| borrowed())?
            .authenticate_original_prepare_data(&commit.prepare)?;
        // The quote authenticates every typed Prepare field, including the exact
        // source-signed allocation and full ordered roster; no copied token alone.
        if request.transaction_id != commit.prepare.transaction_id {
            return Err(refused());
        }
        drop(request);

        let state = self.original_restore_responses
            [index(PacketCompleteRestoreTransferPhase::Prepare)]
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| borrowed())?;
        if state.phase != Phase::Complete
            || state.request_sequence != commit.prepare_request_sequence
            || state.original.request_id.0.as_ref() != Some(&commit.prepare_request_id)
            || state.original.sequence != commit.prepare_response_sequence
            || blake3::hash(&state.canonical).as_bytes().as_slice()
                != commit.prepare_response_digest.as_slice()
        {
            return Err(refused());
        }
        let projection = CompleteRestoreTransferProjection::from_envelope(&state.original)?;
        let CompleteRestoreTransferProjection::Receipt {
            phase: PacketCompleteRestoreTransferPhase::Prepare,
            receipt,
        } = projection
        else {
            return Err(refused());
        };
        let transfer_token = receipt
            .get("transfer_token")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(refused)?;
        // The fixed proof parser already checked the closed base64 spelling;
        // compare directly against its canonical typed Bytes representation.
        use base64::Engine;
        let mut encoded = [0u8; 44];
        let count = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode_slice(commit.transfer_token.as_slice(), &mut encoded)
            .map_err(|_| refused())?;
        if transfer_token.as_bytes() != &encoded[..count] {
            return Err(refused());
        }

        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| borrowed())?;
        bank.authenticate_completed_send(
            state.literal_slot.ok_or_else(refused)?,
            &state.canonical,
        )?;
        let mut matched = false;
        for frame in bank.frames() {
            if frame.direction != FrameDirection::Incoming
                || !frame.complete
                || frame.transferred != frame.bytes.len()
                || frame.bytes.len() < 4
            {
                continue;
            }
            let body = &frame.bytes[4..];
            if blake3::hash(body).as_bytes().as_slice() != commit.prepare_request_digest.as_slice()
            {
                continue;
            }
            if matched
                || u32::from_be_bytes(frame.bytes[..4].try_into().map_err(|_| refused())?) as usize
                    != body.len()
            {
                return Err(refused());
            }
            let literal_header: [u8; 4] = frame.bytes[..4].try_into().map_err(|_| refused())?;
            if usize::try_from(u32::from_be_bytes(literal_header)).map_err(|_| refused())?
                != body.len()
                || plain_string(borrowed_field(body, "message")?)? != "request"
                || plain_string(borrowed_field(body, "method")?)? != "begin"
                || plain_string(borrowed_field(body, "request_id")?)?
                    != commit.prepare_request_id.as_str()
                || borrowed_u64_field(body, "sequence")? != commit.prepare_request_sequence.get()
            {
                return Err(refused());
            }
            matched = true;
        }
        if !matched {
            return Err(refused());
        }
        Ok(())
    }

    /// Borrows the same completed native Prepare response after current checks.
    pub(crate) fn original_complete_restore_prepare_response_data(
        &self,
        commit: &crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreCommitRequest,
    ) -> Result<std::cell::Ref<'_, Envelope>, ProviderError> {
        self.authenticate_original_complete_restore_prepare_data(commit)?;
        let state = self.original_restore_responses
            [index(PacketCompleteRestoreTransferPhase::Prepare)]
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| borrowed())?;
        Ok(std::cell::Ref::map(state, |state| &state.original))
    }
}

impl<S: ProviderStream> Connection<S> {
    /// Borrows the actual completed Commit response beside its genuine held owner.
    ///
    /// A later operation may have advanced the read sequence or installed its
    /// own physical cut. This checks the immutable completed original and sent
    /// literal, without renewing Commit or applying a latest-request predicate.
    pub(crate) fn original_complete_restore_commit_response_data(
        &self,
        held: &crate::reference_packet::service::ack_emitter::VerifiedCompleteRestorationHeld,
        commit: &Envelope,
    ) -> Result<std::cell::Ref<'_, Envelope>, ProviderError> {
        use super::restore_held_proof::{authenticate_content_bytes, borrowed_field};
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        held.authenticate_current(self, commit)?;
        let owner = self.original_restore_responses
            [index(PacketCompleteRestoreTransferPhase::Commit)]
        .as_ref()
        .ok_or_else(refused)?;
        let state = owner.try_borrow().map_err(|_| borrowed())?;
        if state.phase != Phase::Complete
            || state.request_sequence != commit.sequence
            || state.completed_proof.is_none()
        {
            return Err(refused());
        }
        commit.matches_response(&state.original)?;
        let projection = CompleteRestoreTransferProjection::from_envelope(&state.original)?;
        if !matches!(
            projection,
            CompleteRestoreTransferProjection::Receipt {
                phase: PacketCompleteRestoreTransferPhase::Commit,
                ..
            }
        ) {
            return Err(refused());
        }
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| borrowed())?;
        bank.authenticate_completed_send(
            state.literal_slot.ok_or_else(refused)?,
            &state.canonical,
        )?;
        {
            let evidence = held.original_gate_evidence(self, commit)?;
            authenticate_content_bytes(&evidence.0, &evidence.1)?;
            let body = borrowed_field(&state.canonical, "body")?;
            let result = borrowed_field(body, "result")?;
            crate::protocol_snapshot::owned11::correspondence::content_reference(
                &evidence.0,
                borrowed_field(result, "closed_gate_receipt")?,
            )?;
        }
        drop(bank);
        Ok(std::cell::Ref::map(state, |state| &state.original))
    }
}

impl<S: ProviderStream> Connection<S> {
    /// Authenticates the real verified issuer and complete physical Prepare reply.
    /// This data predicate grants no reconstruction or ephemeral-owner retirement;
    /// the selected endpoint calls it only after its actual publication returns.
    pub(crate) fn authenticate_original_fresh_prepare_handoff_data(
        &self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.authority.ensure_live()?;
        if self.role != EndpointRole::Provider || self.fenced {
            return Err(refused());
        }
        let installed = self.original_restore_inputs.as_ref().ok_or_else(refused)?;
        installed
            .token
            .authenticate_handoff_original_data(self, original)?;
        // This is the exact preallocated six-input custody retained by that
        // issuer. Its real reservations and receiving phase remain mandatory.
        let _custody = self.acknowledge_original_complete_restore_input_custody()?;
        let state = self.original_restore_responses
            [index(PacketCompleteRestoreTransferPhase::Prepare)]
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| borrowed())?;
        if state.phase != Phase::Complete
            || state.request_sequence != original.sequence
            || state.deadline.original_cut() != state.cut
            || state.cut.remaining().is_none()
        {
            return Err(refused());
        }
        original.matches_response(&state.original)?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| borrowed())?;
        bank.authenticate_completed_send(
            state.literal_slot.ok_or_else(refused)?,
            &state.canonical,
        )?;
        installed.token.authenticate_current(self)
    }

    /// Names the actual explicit borrowed/temporary handoff headers.
    pub(crate) const fn original_fresh_prepare_handoff_counter_scratch_data() -> usize {
        std::mem::size_of::<std::cell::Ref<'static, AssignedNativeRestoreResponse>>()
            + std::mem::size_of::<std::cell::Ref<'static, crate::transport::original_frames::OriginalFrameReservation>>()
            + std::mem::size_of::<Rc<RefCell<OriginalCompleteRestoreInputCustody>>>()
            + std::mem::size_of::<std::cell::Ref<'static, OriginalCompleteRestoreInputCustody>>()
            + std::mem::size_of::<std::cell::Ref<'static, crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestorePrepareRequest>>()
    }
}

#[path = "restore_response/settled.rs"]
mod settled_history;
