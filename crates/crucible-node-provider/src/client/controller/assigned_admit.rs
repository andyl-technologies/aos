//! Retains one assigned canonical-ACK Admit before source signing and I/O.
//!
//! The original sequence, request ID, literal slot and canonical buffer belong
//! to the controller before a signer can inspect the envelope. Dropping a
//! borrowed preparation leaves that state retained and blocks ordinary calls.
//! Sealing changes only the registered proof extension. Publication uses those
//! exact bytes and the original deadline; it cannot assign a fresh sequence.

use super::*;
use crate::operational_time::OperationalDeadline;
use crate::reference_packet::service::ack_emitter::{
    MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES, PACKET_CANONICAL_ACK_ADMISSION_FEATURE,
    PacketCanonicalAckAdmissionProof,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Unsigned,
    Sealing,
    Sealed,
    Publishing,
    Complete,
}

pub(super) struct AssignedOriginalCanonicalAckAdmit {
    original: Envelope,
    bytes: Vec<u8>,
    literal_slot: Option<usize>,
    cut: OperationalDeadline,
    phase: Phase,
    response: Option<Envelope>,
}

impl AssignedOriginalCanonicalAckAdmit {
    pub(super) fn validate_owned_snapshot(&self) -> Result<(), ProviderError> {
        if self.phase != Phase::Complete || self.response.is_none() || self.literal_slot.is_none() {
            return Err(ProviderError::Correlation(
                "owned protocol assigned Admit unsettled",
            ));
        }
        Ok(())
    }

    pub(super) fn observe_owned_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.validate_owned_snapshot()?;
        let Self {
            original,
            bytes,
            literal_slot: _,
            cut: _,
            phase: _,
            response,
        } = self;
        observer.observe(original)?;
        observer.vector::<u8>(bytes.capacity())?;
        observer.observe(response)
    }

    pub(super) fn original_cut(&self) -> OperationalDeadline {
        self.cut
    }

    pub(super) fn owned_protocol_view(&self) -> impl serde::Serialize + '_ {
        (
            "complete",
            &self.original,
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(&self.bytes),
            self.bytes.capacity(),
            self.literal_slot,
            &self.response,
            "original-physical-cut-retained-by-opaque-owner-not-portable-time",
        )
    }
}

/// Exclusively borrows a controller-owned assigned original Admit preparation.
///
/// Dropping this wrapper leaves its originals, reserved lifetime ID and bank
/// slot in the same controller. It grants no source or native marker authority.
pub struct PreparedOriginalCanonicalAckAdmit<'a> {
    controller: &'a mut CnpController,
}

impl CnpController {
    /// Borrows the same completed original protocol Admit and its actual raw reply.
    ///
    /// This reauthenticates the retained emitter, origin, controller and codec.
    /// It copies no body, decodes no result, renews no deadline and issues no world
    /// or native permission. The source independently checks full current graph,
    /// world, dispatch, binding and receipt correspondence before any transition.
    ///
    /// # Errors
    /// Refuses another emitter/actor/registration, absent or incomplete assigned
    /// state, or a missing original raw response. Uncertainty retains all owners.
    pub fn original_completed_canonical_ack_admit<'a>(
        &'a self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<CompletedOriginalCanonicalAckAdmit<'a>, ProviderError> {
        emitter.authenticate_original(self)?;
        let assigned = self
            .original_ack_admit
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "completed original canonical ACK Admit absent",
            ))?;
        if assigned.phase != Phase::Complete {
            return Err(ProviderError::Correlation(
                "original canonical ACK Admit incomplete",
            ));
        }
        let response = assigned
            .response
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "completed canonical ACK Admit raw response absent",
            ))?;
        Ok(CompletedOriginalCanonicalAckAdmit {
            original: &assigned.original,
            response,
        })
    }

    /// Prepares one exact assigned Admit before signing or transport effects.
    ///
    /// The registered proof has fixed finite credit. Original request and
    /// response journal room, frame slot and canonical buffer are admitted
    /// before the source sees the assigned envelope. Failure after assignment
    /// retains the state; no other request may consume its sequence or ID.
    ///
    /// # Errors
    /// Refuses another emitter/origin, old or pending originals, unnegotiated
    /// admission proof, oversized data, exhausted capacity or failed reservation.
    pub fn prepare_original_canonical_ack_admit<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        request: AdmitRequest,
    ) -> Result<PreparedOriginalCanonicalAckAdmit<'a>, ProviderError> {
        self.prepare_original_canonical_ack_admit_inner(emitter, request_id, request, false)
    }

    /// Prepares the selected initial Admit beneath the existing physical cut.
    ///
    /// The private Source action authenticates the same initial lifecycle before
    /// calling this method. The keyed issuer, literal slot and original proof
    /// validations remain identical to ordinary assigned Admit.
    ///
    /// # Errors
    /// Refuses invalid/used originals, expired cuts or exhausted finite custody.
    pub fn prepare_original_initial_canonical_ack_admit<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        request: AdmitRequest,
    ) -> Result<PreparedOriginalCanonicalAckAdmit<'a>, ProviderError> {
        self.prepare_original_canonical_ack_admit_inner(emitter, request_id, request, true)
    }

    fn prepare_original_canonical_ack_admit_inner<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        request: AdmitRequest,
        initial: bool,
    ) -> Result<PreparedOriginalCanonicalAckAdmit<'a>, ProviderError> {
        emitter.authenticate_original(self)?;
        if initial {
            self.custody
                .authenticate_original_host_initial_admit_order()?;
        }
        if self.original_ack_admit.is_some() || self.original(&request_id).is_some() {
            return Err(ProviderError::Conflict(
                "assigned original Admit already reserved",
            ));
        }
        if !request.extensions.is_empty()
            || !self
                .authority()
                .envelope_extensions()
                .contains(PACKET_CANONICAL_ACK_ADMISSION_FEATURE)
        {
            return Err(ProviderError::Correlation(
                "assigned Admit proof not negotiated",
            ));
        }
        let maximum = self.maximum_frame()?;
        count_serialized(&request, maximum)?;
        request.validate()?;
        let body =
            serde_json::to_value(request).map_err(crucible_node_contract::ContractError::from)?;
        let Value::Object(body) = body else {
            return Err(ProviderError::Frame("assigned Admit body not object"));
        };
        let (sequence, cut) = if initial {
            self.session.begin_original_initial_ack_admit(self.budget)?
        } else {
            self.session.begin_original_ack_admit(self.budget)?
        };
        let original = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(self.authority().session_id().clone())),
            incarnation_id: Nullable(Some(self.authority().incarnation_id().clone())),
            node_id: Nullable(Some(self.route.node.clone())),
            execution_owner_id: Nullable(Some(self.route.execution_owner.clone())),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(request_id)),
            operation_id: Nullable(None),
            sequence,
            method: Method::Admit,
            body,
            extensions: Extensions::new(),
        };
        let final_maximum = crate::connection::serialized_credit(&original, maximum)?
            .checked_add(PACKET_CANONICAL_ACK_ADMISSION_FEATURE.len() + 3)
            .and_then(|bytes| bytes.checked_add(MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(ProviderError::ResourceExhausted(
                "assigned Admit complete proof frame credit",
            ))?;
        self.preflight_source_reply(
            1,
            0,
            final_maximum
                .checked_add(maximum)
                .ok_or(ProviderError::ResourceExhausted(
                    "assigned Admit journal extent",
                ))?,
            0,
            0,
        )?;
        self.original_ack_admit = Some(AssignedOriginalCanonicalAckAdmit {
            original,
            bytes: Vec::new(),
            literal_slot: None,
            cut,
            phase: Phase::Unsigned,
            response: None,
        });
        let state = self
            .original_ack_admit
            .as_mut()
            .ok_or(ProviderError::Correlation("assigned Admit owner missing"))?;
        state
            .bytes
            .try_reserve_exact(final_maximum)
            .map_err(|_| ProviderError::ResourceExhausted("assigned Admit canonical buffer"))?;
        self.session.reserve_original_ack_admit(
            &state.original,
            final_maximum,
            &mut state.literal_slot,
        )?;
        Ok(PreparedOriginalCanonicalAckAdmit { controller: self })
    }

    /// Resumes only this same retained unattempted signing or sealed preparation.
    ///
    /// No sequence, deadline, ID, frame slot or buffer is renewed.
    ///
    /// # Errors
    /// Refuses another emitter/origin, absent state, changed or expired cut or
    /// a sealing/publication attempt that failed or already completed.
    pub fn resume_original_canonical_ack_admit<'a>(
        &'a mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<PreparedOriginalCanonicalAckAdmit<'a>, ProviderError> {
        emitter.authenticate_original(self)?;
        let state = self
            .original_ack_admit
            .as_ref()
            .ok_or(ProviderError::Correlation("assigned Admit original absent"))?;
        if !matches!(state.phase, Phase::Unsigned | Phase::Sealed) || state.literal_slot.is_none() {
            return Err(ProviderError::Conflict(
                "assigned Admit cannot resume attempted state",
            ));
        }
        self.session
            .authenticate_original_ack_admit_cut(state.original.sequence, state.cut)?;
        Ok(PreparedOriginalCanonicalAckAdmit { controller: self })
    }

    pub(super) fn ensure_no_pending_original_ack_admit(&self) -> Result<(), ProviderError> {
        self.ensure_no_pending_original_complete_restore()?;
        if self
            .original_ack_admit
            .as_ref()
            .is_some_and(|state| state.phase != Phase::Complete)
        {
            return Err(ProviderError::Conflict(
                "assigned original Admit remains retained",
            ));
        }
        Ok(())
    }
}

impl PreparedOriginalCanonicalAckAdmit<'_> {
    /// Reauthenticates the actual retained emitter without exposing the controller.
    ///
    /// # Errors
    /// Refuses foreign/revoked emitter, changed codec or the original operation cut.
    pub fn authenticate_original_emitter(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(self.controller)?;
        let state = self
            .controller
            .original_ack_admit
            .as_ref()
            .ok_or(ProviderError::Correlation("assigned Admit owner absent"))?;
        if state.phase == Phase::Complete {
            return Ok(());
        }
        self.controller
            .session
            .authenticate_original_ack_admit_cut(state.original.sequence, state.cut)
    }

    /// Borrows the exact assigned original envelope before or after sealing.
    ///
    /// # Errors
    /// Refuses foreign origin, absent original state or changed/expired cut.
    pub fn original(&self) -> Result<&Envelope, ProviderError> {
        self.controller.protocol_owner.ensure_current()?;
        let state = self
            .controller
            .original_ack_admit
            .as_ref()
            .ok_or(ProviderError::Correlation("assigned Admit owner absent"))?;
        if state.phase != Phase::Complete {
            self.controller
                .session
                .authenticate_original_ack_admit_cut(state.original.sequence, state.cut)?;
        }
        Ok(&state.original)
    }

    /// Borrows digests only from this same connection's actual original Hello bank.
    ///
    /// # Errors
    /// Refuses another journal, actor, registration, selected codec or raw frame.
    pub fn original_canonical_ack_hello_frame_digests(
        &self,
        journal: &super::super::OriginalHelloJournal,
    ) -> Result<crate::native_hello::OriginalHelloFrameDigests, ProviderError> {
        self.controller
            .original_canonical_ack_hello_frame_digests(journal)
    }

    /// Seals only the registered proof into the same original literal frame slot.
    ///
    /// Proof validation is syntax only. Authentic source/native associations and
    /// MAC verification remain the private issuers' separate responsibility.
    /// Failure or unwind after mutation retains the original and blocks retries.
    ///
    /// # Errors
    /// Refuses a changed original/phase, invalid proof, insufficient finite credit,
    /// revoked codec, failed encoding, journal or original bank reservation.
    pub fn seal(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        proof: PacketCanonicalAckAdmissionProof,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_emitter(emitter)?;
        proof.validate_data()?;
        crate::connection::serialized_credit(&proof, MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES)?;
        let state = self
            .controller
            .original_ack_admit
            .as_mut()
            .ok_or(ProviderError::Correlation("assigned Admit owner absent"))?;
        if state.phase != Phase::Unsigned || !state.original.extensions.is_empty() {
            return Err(ProviderError::Conflict(
                "assigned Admit sealing already attempted",
            ));
        }
        state.phase = Phase::Sealing;
        let proof =
            serde_json::to_value(proof).map_err(crucible_node_contract::ContractError::from)?;
        state
            .original
            .extensions
            .insert(PACKET_CANONICAL_ACK_ADMISSION_FEATURE.into(), proof);
        self.controller.session.seal_original_ack_admit(
            &mut self.controller.custody,
            &state.original,
            &mut state.bytes,
            state.literal_slot,
        )?;
        state.phase = Phase::Sealed;
        Ok(())
    }

    /// Publishes the same sealed bytes and stores its reply before returning.
    ///
    /// Neither sequence nor absolute deadline is renewed. The returned response
    /// is data; native acknowledgement-mechanism activation requires its opaque
    /// authenticated Admit token and source-owned original association.
    ///
    /// # Errors
    /// Refuses an occupied result slot, changed owner/cut, repeated attempt,
    /// partial write, malformed or foreign response or unavailable content.
    ///
    /// # Panics
    /// Trusted schema/supervision callbacks may unwind; the controller retains
    /// the assigned originals and progress outside those callbacks.
    pub fn publish_into(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), ProviderError> {
        self.publish_into_inner(emitter, completed, false)
    }

    /// Publishes the selected initial Admit with its closed pretyped reply guard.
    ///
    /// The actual typed reply and raw original reach the Source and assigned
    /// owning slots before any post-receive check or containment callback.
    /// The Source's full binding/MAC/currentness checks remain mandatory.
    ///
    /// # Errors
    /// Refuses changed original state, expired cuts, occupied output, malformed
    /// replies or transport uncertainty, retaining every surviving owner.
    pub fn publish_initial_into(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), ProviderError> {
        self.publish_into_inner(emitter, completed, true)
    }

    fn publish_into_inner(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        completed: &mut Option<ResponseBody>,
        initial: bool,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_emitter(emitter)?;
        if completed.is_some() {
            return Err(ProviderError::Conflict(
                "assigned Admit result slot occupied",
            ));
        }
        let state = self
            .controller
            .original_ack_admit
            .as_mut()
            .ok_or(ProviderError::Correlation("assigned Admit owner absent"))?;
        if state.phase != Phase::Sealed {
            return Err(ProviderError::Conflict(
                "assigned Admit publication already attempted or unsealed",
            ));
        }
        state.phase = Phase::Publishing;
        if initial {
            self.controller
                .session
                .publish_original_initial_ack_admit_into(
                    &mut self.controller.custody,
                    &state.original,
                    &state.bytes,
                    state.literal_slot,
                    state.cut,
                    &mut state.response,
                    completed,
                )?;
            state.phase = Phase::Complete;
            return Ok(());
        }
        let reply = self.controller.session.publish_original_ack_admit(
            &mut self.controller.custody,
            &state.original,
            &state.bytes,
            state.literal_slot,
            state.cut,
        )?;
        state.response = Some(reply);
        let response = state.response.as_ref().ok_or(ProviderError::Correlation(
            "assigned Admit retained response absent",
        ))?;
        let request = decode_request(state.original.method, &state.original.body)?;
        *completed = Some(decode_response(&request, &response.body)?);
        state.phase = Phase::Complete;
        Ok(())
    }
}

#[cfg(test)]
#[path = "assigned_admit_tests.rs"]
mod tests;

/// Borrows exact controller-owned completed protocol data without granting rights.
///
/// The controller authenticates the original emitter before issuing this view.
/// Subsequent source/world transitions separately recheck current original
/// associations; these immutable envelope references are not a permission token.
pub struct CompletedOriginalCanonicalAckAdmit<'a> {
    original: &'a Envelope,
    response: &'a Envelope,
}

impl<'a> CompletedOriginalCanonicalAckAdmit<'a> {
    /// Borrows the exact assigned request, including its original proof extension.
    pub fn original(&self) -> &'a Envelope {
        self.original
    }

    /// Borrows the actual retained raw response, before owning result normalization.
    pub fn response(&self) -> &'a Envelope {
        self.response
    }
}

impl AssignedOriginalCanonicalAckAdmit {
    pub(super) fn borrowed_settled_history_data(&self) -> impl serde::Serialize + '_ {
        let Self {
            original,
            bytes,
            literal_slot,
            cut: _,
            phase,
            response,
        } = self;
        (
            "source-private.sdk-assigned-admit-current/17",
            original,
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(bytes),
            bytes.capacity(),
            literal_slot,
            match phase {
                Phase::Unsigned => "unsigned",
                Phase::Sealing => "sealing",
                Phase::Sealed => "sealed",
                Phase::Publishing => "publishing",
                Phase::Complete => "complete",
            },
            response,
            "historical-nonrenewable-operational-cut",
        )
    }

    pub(super) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.original)?;
        observer.vector::<u8>(self.bytes.capacity())?;
        observer.observe(&self.response)?;

        Ok(())
    }
}

fn settled_field_views<T>(
    _: impl FnOnce(&'static AssignedOriginalCanonicalAckAdmit) -> T,
) -> usize {
    std::mem::size_of::<T>()
}

impl AssignedOriginalCanonicalAckAdmit {
    pub(super) fn settled_history_counter_scratch_data() -> usize {
        settled_field_views(|value| {
            let projected = value.borrowed_settled_history_data();
            (projected, Some(value.borrowed_settled_history_data()))
        }) + settled_field_views(|value| {
            let AssignedOriginalCanonicalAckAdmit {
                original,
                bytes,
                literal_slot,
                cut,
                phase,
                response,
            } = value;
            (original, bytes, literal_slot, cut, phase, response)
        }) + std::mem::size_of::<&Self>()
            + std::mem::size_of::<Option<&Self>>()
            + std::mem::size_of::<&mut crate::retained_metadata::MetadataObserver<'static>>()
            + std::mem::size_of::<Result<(), ProviderError>>()
    }
}
