//! Advances distinct seven-bank originals under the actual existing Prepare cut.
//!
//! Baseline Blob framing is shared with ordinary CNP. The selected18 capsule,
//! original live Session and its real retained Prepare establish this route;
//! no old six-input selection, FreshQuery or mapping witness is consulted.

use super::*;
use crate::connection::{ReceivedBody, ReceivedFrame};
use crate::envelope::Method;
use crate::operational_time::OperationalDeadline;

impl ClientSession {
    /// Checks the same live selected actor without replacing its original cut.
    ///
    /// # Errors
    /// Refuses changed selection, pending correlation, loss or expiration.
    pub(in crate::client) fn authenticate_native_import18_upload_cut_data(
        &self,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.connection.preflight_native_import18_upload_data()?;
        if self.deadline.original_cut() != cut
            || cut.remaining().is_none()
            || self.original_response_loss.is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Joins the first upload to the actual next sequence after Prepare.
    ///
    /// # Errors
    /// Refuses another cut or intervening original traffic.
    pub(in crate::client) fn authenticate_native_import18_upload_start_data(
        &self,
        original: &Envelope,
        cut: OperationalDeadline,
    ) -> Result<(), ProviderError> {
        self.authenticate_native_import18_upload_cut_data(cut)?;
        if self.sequence != original.sequence.checked_add(U64::new(1))? {
            return Err(invalid());
        }
        Ok(())
    }

    /// Borrows the current original sequence under the unchanged upload cut.
    ///
    /// # Errors
    /// Refuses expiration, changed actor or sequence exhaustion.
    pub(in crate::client) fn native_import18_upload_sequence_data(
        &self,
        cut: OperationalDeadline,
    ) -> Result<U64, ProviderError> {
        self.authenticate_native_import18_upload_cut_data(cut)?;
        self.sequence.checked_add(U64::new(1))?;
        Ok(self.sequence)
    }

    /// Retains each original and whole terminal before later ACK inspection.
    ///
    /// # Errors
    /// Refuses reused IDs, changed cut/sequence, capacity or uncertain IO;
    /// initialized custody and the whole received terminal remain retained.
    pub(in crate::client) fn exchange_native_import18_upload_raw_into_data(
        &mut self,
        custody: &mut ClientCustody,
        original: &Envelope,
        cut: OperationalDeadline,
        raw: &mut Option<crate::transport::RetainedFrame>,
        profile: &mut crate::retained_metadata::NativeImport18JsonMetadataProfileData,
    ) -> Result<(), ProviderError> {
        if raw.is_some()
            || original.sequence != self.native_import18_upload_sequence_data(cut)?
            || !matches!(
                original.method,
                Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
            )
            || !original.extensions.is_empty()
            || original.node_id.0.is_some()
            || original.execution_owner_id.0.is_some()
            || original.capture_owner_id.0.is_some()
            || original.operation_id.0.is_some()
        {
            return Err(invalid());
        }
        let id = original.request_id.0.as_ref().ok_or_else(invalid)?;
        if custody.controller.contains_key(id)
            || custody.controller.len() >= custody.maximum_requests
        {
            return Err(invalid());
        }
        let bytes = envelope_bytes(original)?;
        let room =
            usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| invalid())?;
        custody.ensure_journal_room(bytes.checked_add(room).ok_or_else(invalid)?)?;
        let identity = original.request_hash(RequestOrigin::Controller)?;
        custody.retain_journal_bytes(bytes)?;
        custody.controller.insert(
            id.clone(),
            ClientOriginal {
                request: original.clone(),
                identity,
                response: None,
            },
        );
        self.native_import18_upload_sequence_data(cut)?;
        self.send(original.clone())?;
        self.connection
            .receive_native_import18_raw_into_data(original, raw, profile)
    }

    /// Decodes one exact retained upload reply after independent row admission.
    ///
    /// # Errors
    /// Retains raw and typed partials on changed cut, syntax or correlation.
    pub(in crate::client) fn decode_native_import18_upload_into_data(
        &mut self,
        custody: &mut ClientCustody,
        original: &Envelope,
        cut: OperationalDeadline,
        raw: &crate::transport::RetainedFrame,
        response: &mut Option<Envelope>,
        received: &mut Option<ReceivedFrame>,
    ) -> Result<(), ProviderError> {
        self.authenticate_native_import18_raw_data(original, cut, raw)?;
        self.connection
            .decode_native_import18_raw_into_data(original, raw, response, received)?;
        let frame = received.as_ref().ok_or_else(invalid)?;
        if !matches!(frame.body, ReceivedBody::Response(_)) || !frame.envelope.extensions.is_empty()
        {
            return Err(invalid());
        }
        original.matches_response(&frame.envelope)?;
        custody.retain_journal_bytes(envelope_bytes(&frame.envelope)?)?;
        let id = original.request_id.0.as_ref().ok_or_else(invalid)?;
        custody.controller.get_mut(id).ok_or_else(invalid)?.response = Some(frame.envelope.clone());
        self.authenticate_native_import18_upload_cut_data(cut)
    }
}
