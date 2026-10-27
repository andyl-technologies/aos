//! Source-selected confirmation publication checks on the same original stream.
//!
//! Byte arguments contain literal four-byte frame headers. These checks observe
//! the existing bank without reserving IDs, slots or bytes. Incoming ACKs use the
//! full negotiated raw ceiling until a distinct genuine emitter association is
//! implemented. Host lifetime custody, whole memory admission and the source
//! settlement issuer remain separate requirements.

use super::*;

impl<S: ProviderStream> Connection<S> {
    /// Checks the same incoming Poll and the actually installed closed selection.
    ///
    /// # Errors
    /// Refuses a foreign actor, unselected codec, changed negotiation, non-Poll
    /// context or any unrelated outstanding original correlation.
    pub fn authenticate_native5_confirmation_poll(
        &self,
        original_poll: &Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_confirmation_context(original_poll)?;
        self.guard
            .authenticate_incoming_confirmation(original_poll)?;
        self.authority.ensure_live()
    }

    fn authenticate_native5_confirmation_context(
        &self,
        original_poll: &Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider {
            return Err(ProviderError::Correlation(
                "confirmation requires native provider endpoint",
            ));
        }
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "confirmation source codec absent",
            ))?;
        codec.authenticate_confirmation_selection(&self.authority)?;
        let projection = ConfirmationProjection::from_envelope(original_poll)?;
        if projection.after.is_some()
            || original_poll
                .body
                .get("after_observation_sequence")
                .and_then(serde_json::Value::as_str)
                != Some("0")
        {
            return Err(ProviderError::Correlation(
                "confirmation Poll request changed",
            ));
        }
        self.authority.ensure_live()
    }

    pub(crate) fn authenticate_prepared_canonical_ack_poll(
        &self,
        original_poll: &Envelope,
        originals: &[Envelope],
    ) -> Result<(), ProviderError> {
        self.original_canonical_blob_ack_framed_bytes()?;
        self.authenticate_native5_confirmation_context(original_poll)?;
        self.guard
            .authenticate_prepared_confirmation(original_poll, originals)
    }

    /// Admits prospective literal bytes and slots without changing any bank.
    ///
    /// Outgoing bytes must include every header and exact canonical body extent.
    /// The already-received Poll is in the current bank; incoming ACK count covers
    /// only future proof replies. This grants neither allocation nor publication
    /// permission without the caller's complete planned-frame and whole-budget
    /// preflight. No retired slot or request lifetime credit is refunded.
    ///
    /// # Errors
    /// Refuses mismatched original Poll, incomplete bank, insufficient raw ACK
    /// allowance, count/sequence overflow or exhausted lifetime slots and bytes.
    pub fn preflight_confirmation_publication(
        &self,
        original_poll: &Envelope,
        outgoing_count: usize,
        canonical_outgoing_framed_bytes: usize,
        incoming_ack_count: usize,
        incoming_raw_framed_bytes: usize,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_confirmation_poll(original_poll)?;
        let maximum_raw = allowance(self.authority.limits().frame_bytes.get())?
            .checked_add(4)
            .ok_or(ProviderError::ResourceExhausted(
                "confirmation framed byte overflow",
            ))?;
        self.preflight_confirmation_publication_with_maximum(
            original_poll,
            outgoing_count,
            canonical_outgoing_framed_bytes,
            incoming_ack_count,
            incoming_raw_framed_bytes,
            maximum_raw,
        )
    }

    /// Admits a confirmation suffix under this actor's genuine keyed ACK marker.
    ///
    /// The marker supplies the compiled complete canonical ceiling. No caller
    /// scalar or host-side emitter lease selects a restricted native reader.
    ///
    /// # Errors
    /// Refuses an absent or replaced marker, unrelated Poll or insufficient
    /// complete lifetime byte, slot, request-ID and sequence credit.
    pub fn preflight_original_canonical_blob_ack_publication(
        &self,
        original_poll: &Envelope,
        outgoing_count: usize,
        canonical_outgoing_framed_bytes: usize,
        incoming_ack_count: usize,
        incoming_raw_framed_bytes: usize,
    ) -> Result<(), ProviderError> {
        let maximum_raw = self.original_canonical_blob_ack_framed_bytes()?;
        self.preflight_confirmation_publication_with_maximum(
            original_poll,
            outgoing_count,
            canonical_outgoing_framed_bytes,
            incoming_ack_count,
            incoming_raw_framed_bytes,
            maximum_raw,
        )
    }

    fn preflight_confirmation_publication_with_maximum(
        &self,
        original_poll: &Envelope,
        outgoing_count: usize,
        canonical_outgoing_framed_bytes: usize,
        incoming_ack_count: usize,
        incoming_raw_framed_bytes: usize,
        maximum_raw: usize,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_confirmation_poll(original_poll)?;
        let required_incoming =
            incoming_ack_count
                .checked_mul(maximum_raw)
                .ok_or(ProviderError::ResourceExhausted(
                    "confirmation ACK byte overflow",
                ))?;
        let minimum_outgoing =
            outgoing_count
                .checked_mul(5)
                .ok_or(ProviderError::ResourceExhausted(
                    "confirmation outgoing byte overflow",
                ))?;
        if incoming_ack_count < 2
            || incoming_ack_count.checked_add(1) != Some(outgoing_count)
            || incoming_raw_framed_bytes < required_incoming
            || canonical_outgoing_framed_bytes < minimum_outgoing
        {
            return Err(ProviderError::ResourceExhausted(
                "confirmation complete suffix byte/count allowance",
            ));
        }
        self.guard
            .preflight_confirmation_sequences(outgoing_count, incoming_ack_count)?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "confirmation literal bank absent",
            ))?;
        let bank = bank
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("confirmation literal bank borrowed"))?;
        let journal = allowance(self.authority.limits().journal_entries.get())?;
        if bank
            .outgoing_original_id_slots()
            .checked_add(incoming_ack_count)
            .is_none_or(|count| count > journal)
        {
            return Err(ProviderError::ResourceExhausted(
                "confirmation conservative lifetime original journal",
            ));
        }
        bank.preflight_framed_suffix(
            outgoing_count,
            canonical_outgoing_framed_bytes,
            incoming_ack_count,
            incoming_raw_framed_bytes,
        )?;
        self.authenticate_native5_confirmation_poll(original_poll)
    }

    /// Checks the complete retained prospective plan and exact future ID roster.
    ///
    /// The iterator is replayable and borrowed; this method retains no plan copy.
    /// Comparisons conservatively reject any ID in either original direction,
    /// including completed responses. The caller separately charges bounded
    /// baseline body decoding and canonical sizing before invoking this method.
    ///
    /// # Errors
    /// Refuses invalid frames, duplicate/history IDs, missing final response,
    /// oversized body, count overflow or unavailable complete suffix credit.
    pub fn preflight_original_confirmation_plan<'a>(
        &self,
        original_poll: &Envelope,
        frames: impl Iterator<Item = &'a Envelope> + Clone,
    ) -> Result<(usize, usize, usize), ProviderError> {
        self.preflight_confirmation_plan_with_ack_scope(original_poll, frames, false)
    }

    /// Checks the exact complete plan under genuine keyed canonical ACK admission.
    ///
    /// # Errors
    /// Refuses an absent or replaced marker, changed scope, malformed frames,
    /// lifetime ID reuse or insufficient complete suffix credit.
    pub fn preflight_original_canonical_blob_ack_plan<'a>(
        &self,
        original_poll: &Envelope,
        frames: impl Iterator<Item = &'a Envelope> + Clone,
    ) -> Result<(usize, usize, usize), ProviderError> {
        self.preflight_confirmation_plan_with_ack_scope(original_poll, frames, true)
    }

    fn preflight_confirmation_plan_with_ack_scope<'a>(
        &self,
        original_poll: &Envelope,
        frames: impl Iterator<Item = &'a Envelope> + Clone,
        canonical_ack_scope: bool,
    ) -> Result<(usize, usize, usize), ProviderError> {
        self.authenticate_native5_confirmation_poll(original_poll)?;
        let mut count = 0usize;
        let mut requests = 0usize;
        let mut bytes = 0usize;
        let maximum = allowance(self.authority.limits().frame_bytes.get())?;
        for (index, frame) in frames.clone().enumerate() {
            self.preflight_original_confirmation_frame(original_poll, frame)?;
            count = count
                .checked_add(1)
                .ok_or(ProviderError::ResourceExhausted(
                    "confirmation plan frame count",
                ))?;
            if count > 4096 {
                return Err(ProviderError::ResourceExhausted(
                    "confirmation plan frame bank",
                ));
            }
            bytes = bytes
                .checked_add(super::prepared::serialized_credit(frame, maximum)?)
                .and_then(|value| value.checked_add(4))
                .ok_or(ProviderError::ResourceExhausted(
                    "confirmation plan framed bytes",
                ))?;
            if frame.message == MessageKind::Request {
                requests = requests
                    .checked_add(1)
                    .ok_or(ProviderError::ResourceExhausted(
                        "confirmation plan request count",
                    ))?;
                let id = frame
                    .request_id
                    .0
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "confirmation plan request ID absent",
                    ))?;
                let bank = self
                    .original_frames
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "confirmation plan literal bank absent",
                    ))?;
                let bank = bank
                    .try_borrow()
                    .map_err(|_| ProviderError::Correlation("confirmation plan bank borrowed"))?;
                if bank.contains_original_id(id.as_str())
                    || original_poll.request_id.0.as_ref() == Some(id)
                    || frames
                        .clone()
                        .take(index)
                        .any(|prior| prior.request_id.0.as_ref() == Some(id))
                {
                    return Err(ProviderError::Conflict(
                        "confirmation plan reuses a lifetime original ID",
                    ));
                }
            } else if frames.clone().nth(index + 1).is_some() {
                return Err(ProviderError::Correlation(
                    "confirmation terminal precedes remaining proof frames",
                ));
            }
        }
        if requests.checked_add(1) != Some(count) {
            return Err(ProviderError::Correlation(
                "confirmation plan has no single final response",
            ));
        }
        let maximum_raw = if canonical_ack_scope {
            self.original_canonical_blob_ack_framed_bytes()?
        } else {
            maximum
                .checked_add(4)
                .ok_or(ProviderError::ResourceExhausted("confirmation ACK framing"))?
        };
        let raw = requests
            .checked_mul(maximum_raw)
            .ok_or(ProviderError::ResourceExhausted(
                "confirmation ACK suffix overflow",
            ))?;
        if canonical_ack_scope {
            self.preflight_original_canonical_blob_ack_publication(
                original_poll,
                count,
                bytes,
                requests,
                raw,
            )?;
        } else {
            self.preflight_confirmation_publication(original_poll, count, bytes, requests, raw)?;
        }
        Ok((count, bytes, requests))
    }

    /// Checks an exact prospective proof request or final confirmation response.
    ///
    /// This retains the ordinary installed body verifier and baseline framing
    /// bounds. It does not register a request, encode a journal entry or send I/O.
    /// The caller retains planned owners outside any callback or failure path.
    ///
    /// # Errors
    /// Refuses a changed Poll, unrelated frame scope, mismatched receipt or
    /// invalid/oversized body under the same installed immutable verifier.
    pub fn preflight_original_confirmation_frame(
        &self,
        original_poll: &Envelope,
        planned: &Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_confirmation_poll(original_poll)?;
        match planned.message {
            MessageKind::Request
                if matches!(
                    planned.method,
                    Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
                ) && planned.extensions.is_empty()
                    && planned.node_id == original_poll.node_id
                    && planned.capture_owner_id == original_poll.capture_owner_id
                    && planned.execution_owner_id == original_poll.execution_owner_id
                    && planned.operation_id == original_poll.operation_id => {}
            MessageKind::Response if planned.method == Method::Poll => {
                original_poll.matches_response(planned)?;
                let original = ConfirmationProjection::from_envelope(original_poll)?;
                let response = ConfirmationProjection::from_envelope(planned)?;
                if original.capture != response.capture || response.after.is_none() {
                    return Err(ProviderError::Correlation(
                        "confirmation receipt changed original Capture",
                    ));
                }
            }
            _ => {
                return Err(ProviderError::Correlation(
                    "confirmation prospective frame scope",
                ));
            }
        }
        super::prepared::serialized_credit(
            planned,
            allowance(self.authority.limits().frame_bytes.get())?,
        )?;
        self.validate_body(planned, false)?;
        self.authenticate_native5_confirmation_poll(original_poll)
    }
}
