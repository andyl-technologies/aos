//! Reads a same-record Blob proof under its unchanged negotiated raw ceiling.
//!
//! Only the actual prepared native source prefix uses this path. Its exact
//! actor, bank, sent literal and still-pending original are authenticated before
//! the read. The parsed Envelope header is checked before method body decoding;
//! raw bytes remain in the same original bank on every refusal.

use super::*;

impl<S: ProviderStream> Connection<S> {
    pub(super) fn receive_original_prepared_blob_proof(
        &mut self,
        record: &ExchangeRecord,
        index: usize,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        self.receive_original_prepared_blob_proof_with_birth(record, index, None)
    }

    pub(super) fn receive_original_prepared_native_birth_proof(
        &mut self,
        record: &ExchangeRecord,
        index: usize,
        scope: &crate::reference_packet::service::ack_emitter::OriginalNativeBirthReadScope<'_>,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        scope.authenticate_connection(self)?;
        self.receive_original_prepared_blob_proof_with_birth(record, index, Some(scope))
    }

    fn receive_original_prepared_blob_proof_with_birth(
        &mut self,
        record: &ExchangeRecord,
        index: usize,
        scope: Option<
            &crate::reference_packet::service::ack_emitter::OriginalNativeBirthReadScope<'_>,
        >,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider
            || !matches!(
                self.native5_codec.as_deref(),
                Some(Native5CodecOwner::NativePacket(_))
            )
        {
            return Err(ProviderError::Correlation(
                "prepared Blob proof native codec absent",
            ));
        }
        // The bank read loan ends before I/O, schema callbacks or containment.
        {
            let sent = record.original_sent_frame(self, index)?;
            let original = sent.original();
            if original.message != MessageKind::Request
                || !matches!(
                    original.method,
                    Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
                )
                || !self
                    .guard
                    .pending_requests()
                    .any(|pending| pending == original)
            {
                return Err(ProviderError::Correlation(
                    "prepared Blob proof original is not pending",
                ));
            }
        }
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        let result = self.receive_original_prepared_blob_proof_inner(record, index, scope);
        match &result {
            Ok(None) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }

    fn receive_original_prepared_blob_proof_inner(
        &mut self,
        record: &ExchangeRecord,
        index: usize,
        scope: Option<
            &crate::reference_packet::service::ack_emitter::OriginalNativeBirthReadScope<'_>,
        >,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        let original = &record.originals[index];
        let Some(value) = self.reader.read()? else {
            return Ok(None);
        };
        let envelope: Envelope =
            serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
        self.authority.with_live(|| {
            self.guard
                .authenticate_prepared_blob_proof_header(original, &envelope)
        })?;
        if let Some(scope) = scope {
            scope.authenticate_connection(self)?;
            scope.authenticate_proof_data(original, &envelope, record)?;
            let slot = self
                .reader
                .original_slot()
                .ok_or(ProviderError::Correlation(
                    "native birth proof literal absent",
                ))?;
            let bank = self
                .original_frames
                .as_ref()
                .ok_or(ProviderError::Correlation("native birth proof bank absent"))?
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("native birth proof bank borrowed"))?;
            let frame = bank.frame(slot).ok_or(ProviderError::Correlation(
                "native birth proof frame absent",
            ))?;
            if !frame.complete || frame.transferred != frame.bytes.len() || frame.bytes.len() < 4 {
                return Err(ProviderError::Correlation(
                    "native birth proof frame incomplete",
                ));
            }
            crate::protocol_snapshot::owned11::correspondence::envelope(
                &envelope,
                &frame.bytes[4..],
            )?;
        }
        let body = self.validate_body(&envelope, true)?;
        self.retain_original_request_id(&envelope, self.reader.original_slot())?;
        self.authority.with_live(|| self.guard.receive(&envelope))?;
        Ok(Some(ReceivedFrame { envelope, body }))
    }
}

#[cfg(test)]
#[path = "exchange_proof_receive_tests.rs"]
mod tests;
