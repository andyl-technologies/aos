//! Prebuilds exact held-proof bytes before effect, then activates after real hold.
//!
//! The endpoint retains this capsule before invoking any schema callback. It
//! owns all canonical buffers, literal proposals and staged correlation nodes.
//! A genuine Held token gates activation; prebuilding data grants no authority.

use super::*;
use crate::reference_packet::service::ack_emitter::VerifiedCompleteRestorationHeld;
use crate::session::OriginalRestoreProofRegistration;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProofPhase {
    Unprepared,
    Prebuilding,
    Prebuilt,
    Activating,
    Activated,
    Failed,
}

#[must_use = "retain the exact proof plan and original connection across effects"]
pub(crate) struct PreparedOriginalRestoreHeldProof<S: ProviderStream> {
    exchange: PreparedExchange<S>,
    commit: Envelope,
    registration: Option<OriginalRestoreProofRegistration>,
    bank_slots: usize,
    bank_digest: Option<blake3::Hash>,
    phase: ProofPhase,
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn unprepared_original_restore_held_proof(
        self,
        commit: Envelope,
        originals: Vec<Envelope>,
    ) -> PreparedOriginalRestoreHeldProof<S> {
        PreparedOriginalRestoreHeldProof {
            exchange: self.unprepared_exchange(originals),
            commit,
            registration: None,
            bank_slots: 0,
            bank_digest: None,
            phase: ProofPhase::Unprepared,
        }
    }
}

impl<S: ProviderStream> PreparedOriginalRestoreHeldProof<S> {
    pub(crate) fn prebuild_in_place(
        &mut self,
        quote: &crate::connection::OriginalRestoreHeldProofAllocationQuote,
    ) -> Result<(), ProviderError> {
        self.exchange.connection.protocol_owner.ensure_current()?;
        if self.phase != ProofPhase::Unprepared {
            return Err(refused());
        }
        self.phase = ProofPhase::Prebuilding;
        quote.begin_original_prebuild(
            &self.exchange.connection,
            self.exchange.record.originals.len(),
        )?;
        self.exchange
            .connection
            .guard
            .authenticate_incoming_complete_restore(&self.commit)?;
        self.exchange.prepare_banks()?;
        self.registration = Some(
            self.exchange
                .connection
                .guard
                .prebuild_original_restore_proof_registration(
                    &self.commit,
                    &self.exchange.record.originals,
                )?,
        );
        let bank = self
            .exchange
            .connection
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| borrowed())?;
        self.bank_slots = bank.frames().count();
        self.bank_digest = Some(planned_bank_digest(&bank)?);
        self.phase = ProofPhase::Prebuilt;
        Ok(())
    }

    /// Borrows the same fresh actor for actual SDK/model installation.
    pub(crate) fn connection_mut(&mut self) -> Result<&mut Connection<S>, ProviderError> {
        self.exchange.connection.protocol_owner.ensure_current()?;
        if self.phase != ProofPhase::Prebuilt {
            return Err(refused());
        }
        self.exchange
            .connection
            .guard
            .authenticate_incoming_complete_restore(&self.commit)?;
        Ok(&mut self.exchange.connection)
    }

    pub(crate) fn activate_original_held(
        &mut self,
        held: &VerifiedCompleteRestorationHeld,
    ) -> Result<(), ProviderError> {
        self.exchange.connection.protocol_owner.ensure_current()?;
        if self.phase != ProofPhase::Prebuilt {
            return Err(refused());
        }
        self.phase = ProofPhase::Activating;
        held.authenticate_current(&self.exchange.connection, &self.commit)?;
        {
            let evidence = held.original_gate_evidence(&self.exchange.connection, &self.commit)?;
            authenticate_body_plan(
                &self.exchange.record,
                &self.commit,
                &evidence.0,
                &evidence.1,
            )?;
            let bank = self
                .exchange
                .connection
                .original_frames
                .as_ref()
                .ok_or_else(refused)?
                .try_borrow()
                .map_err(|_| borrowed())?;
            if bank.frames().count() != self.bank_slots
                || Some(planned_bank_digest(&bank)?) != self.bank_digest
            {
                return Err(refused());
            }
        }
        self.registration
            .as_mut()
            .ok_or_else(refused)?
            .activate(&mut self.exchange.connection.guard, &self.commit)?;
        self.exchange.phase = Phase::Prepared;
        self.phase = ProofPhase::Activated;
        Ok(())
    }

    pub(crate) fn publish(
        &mut self,
        validate: &mut dyn FnMut(&Envelope, &ReceivedFrame) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        if self.phase != ProofPhase::Activated {
            return Err(refused());
        }
        // The existing publication guard retains partial literals/ACKs and fences
        // failure or unwind. This path deliberately uses generic raw ACK limits.
        let result = self.exchange.publish(validate);
        if result.is_err() {
            self.phase = ProofPhase::Failed;
        }
        result
    }

    /// Moves completed owners only after every target slot is checked.
    pub(crate) fn take_completed_into(
        original: &mut Option<Self>,
        connection: &mut Option<Connection<S>>,
        record: &mut Option<ExchangeRecord>,
    ) -> Result<(), ProviderError> {
        let state = original.as_ref().ok_or_else(refused)?;
        state.exchange.connection.protocol_owner.ensure_current()?;
        if state.phase != ProofPhase::Activated
            || state.exchange.phase != Phase::Complete
            || connection.is_some()
            || record.is_some()
        {
            return Err(refused());
        }
        let state = original.take().ok_or_else(refused)?;
        *connection = Some(state.exchange.connection);
        *record = Some(state.exchange.record);
        Ok(())
    }

    pub(crate) fn original_retained_metadata_facts(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        self.exchange.connection.protocol_owner.ensure_current()?;
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        observer.observe(&self.commit)?;
        // This preeffect quote observes actual allocated but unpublished banks;
        // the ordinary completed-record observer correctly refuses that phase.
        let ExchangeRecord {
            originals,
            canonical,
            acknowledgements,
            sent,
            original_slots,
            original_actor,
        } = &self.exchange.record;
        if *sent != 0 || !acknowledgements.is_empty() {
            return Err(refused());
        }
        let (actor, bank) = original_actor.as_ref().ok_or_else(refused)?;
        actor.ensure_current()?;
        use crate::retained_metadata::aliases::MetadataSharedKind;
        observer.shared_original(MetadataSharedKind::ProtocolOwner, actor.as_ref())?;
        observer.shared_original(MetadataSharedKind::FrameBank, bank.as_ref())?;
        bank.try_borrow()
            .map_err(|_| borrowed())?
            .observe_owned11_metadata(&mut observer)?;
        observer.observe(originals)?;
        observer.observe(canonical)?;
        observer.observe(original_slots)?;
        observer.vector::<ReceivedFrame>(acknowledgements.capacity())?;
        if let Some(registration) = &self.registration {
            registration.observe_retained_metadata(&mut observer)?;
        }
        Ok(observer.finish())
    }
}

fn authenticate_body_plan(
    record: &ExchangeRecord,
    commit: &Envelope,
    reference: &crucible_node_format::ContentRef,
    bytes: &[u8],
) -> Result<(), ProviderError> {
    use crate::connection::restore_held_proof::{
        authenticate_base64, authenticate_content_bytes, borrowed_field, borrowed_u64_field,
        decoded_length,
    };
    use crate::protocol_snapshot::owned11::OriginalOwned11Fields as Fields;
    use crate::protocol_snapshot::owned11::correspondence;

    authenticate_content_bytes(reference, bytes)?;
    if record.sent != 0
        || !record.acknowledgements.is_empty()
        || record.originals.len() < 3
        || record.originals.len() != record.canonical.len()
        || record.original_slots.len() != record.originals.len()
    {
        return Err(refused());
    }
    let transfer = record.originals[0]
        .body
        .get("transfer_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(refused)?;
    let mut offset = 0usize;
    for (index, (original, canonical)) in record.originals.iter().zip(&record.canonical).enumerate()
    {
        if original.message != MessageKind::Request
            || !original.extensions.is_empty()
            || original.protocol != commit.protocol
            || original.session_id != commit.session_id
            || original.incarnation_id != commit.incarnation_id
            || original.node_id.0.is_some()
            || original.execution_owner_id.0.is_some()
            || original.capture_owner_id.0.is_some()
            || original.operation_id.0.is_some()
            || original
                .body
                .get("transfer_id")
                .and_then(serde_json::Value::as_str)
                != Some(transfer)
            || original
                .body
                .get("extensions")
                .and_then(serde_json::Value::as_object)
                .is_none_or(|v| !v.is_empty())
        {
            return Err(refused());
        }
        correspondence::envelope(original, canonical)?;
        if index == 0 {
            if original.method != Method::BlobBegin || original.body.len() != 3 {
                return Err(refused());
            }
            let mut envelope = Fields::object(canonical)?;
            let mut body = Fields::object(envelope.named("body")?)?;
            correspondence::content_reference(reference, body.named("content")?)?;
        } else if index + 1 == record.originals.len() {
            if original.method != Method::BlobFinish
                || original.body.len() != 2
                || offset != bytes.len()
            {
                return Err(refused());
            }
        } else {
            if original.method != Method::BlobChunk || original.body.len() != 4 {
                return Err(refused());
            }
            let body = borrowed_field(canonical, "body")?;
            if borrowed_u64_field(body, "offset")?
                != u64::try_from(offset).map_err(|_| refused())?
            {
                return Err(refused());
            }
            let text = original
                .body
                .get("bytes")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(refused)?;
            let length = decoded_length(text)?;
            let end = offset
                .checked_add(length)
                .filter(|n| *n <= bytes.len())
                .ok_or_else(refused)?;
            if length == 0 {
                return Err(refused());
            }
            authenticate_base64(text, &bytes[offset..end])?;
            offset = end;
        }
    }
    Ok(())
}

fn planned_bank_digest(
    bank: &crate::transport::original_frames::OriginalFrameReservation,
) -> Result<blake3::Hash, ProviderError> {
    use crate::transport::original_frames::FrameDirection;
    let mut hash =
        blake3::Hasher::new_derive_key("source-private.complete-restore-prebuilt-held-proof/12");
    for frame in bank.frames() {
        hash.update(&[
            match frame.direction {
                FrameDirection::Incoming => 0,
                FrameDirection::Outgoing => 1,
            },
            u8::from(frame.complete),
        ]);
        hash.update(
            &u64::try_from(frame.transferred)
                .map_err(|_| refused())?
                .to_le_bytes(),
        );
        hash.update(
            &u64::try_from(frame.bytes.len())
                .map_err(|_| refused())?
                .to_le_bytes(),
        );
        hash.update(frame.bytes);
    }
    Ok(hash.finalize())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("prebuilt original held proof changed")
}
fn borrowed() -> ProviderError {
    ProviderError::Conflict("prebuilt original held proof bank borrowed")
}
