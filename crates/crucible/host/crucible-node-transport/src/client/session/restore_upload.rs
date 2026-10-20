//! Sends selected input frames once beneath their single original upload cut.

use super::*;
use crate::{
    connection::ReceivedFrame, envelope::Method, operational_time::OperationalDeadline,
    reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection,
};

impl ClientSession {
    pub(in crate::client) fn preflight_original_restore_upload_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.original_response_loss.is_some()
            || self.original_native5_restore_input_emitter_selection()?
                != Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
        {
            return Err(refused());
        }
        self.connection.preflight_original_restore_upload_data()
    }

    pub(in crate::client) fn begin_original_restore_upload(
        &self,
        budget: Duration,
    ) -> Result<(U64, OperationalDeadline), ProviderError> {
        self.preflight_original_restore_upload_data()?;
        // This is the only deadline reset in the entire six-role publication.
        self.begin_original_ack_admit(budget)
    }

    pub(in crate::client) fn original_restore_upload_sequence(
        &self,
        cut: OperationalDeadline,
    ) -> Result<U64, ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.deadline.original_cut() != cut
            || cut.remaining().is_none()
            || self.original_response_loss.is_some()
        {
            return Err(refused());
        }
        self.sequence.checked_add(U64::new(1))?;
        Ok(self.sequence)
    }

    pub(in crate::client) fn exchange_original_restore_upload_into(
        &mut self,
        custody: &mut ClientCustody,
        original: &Envelope,
        cut: OperationalDeadline,
        received: &mut Option<ReceivedFrame>,
    ) -> Result<(), ProviderError> {
        if received.is_some()
            || original.sequence != self.original_restore_upload_sequence(cut)?
            || !matches!(
                original.method,
                Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
            )
        {
            return Err(refused());
        }
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        // There is deliberately no generic cached-original retry path here.
        if custody.controller.contains_key(id)
            || custody.controller.len() >= custody.maximum_requests
        {
            return Err(refused());
        }
        let bytes = envelope_bytes(original)?;
        let room =
            usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| refused())?;
        custody.ensure_journal_room(bytes.checked_add(room).ok_or_else(refused)?)?;
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
        self.original_restore_upload_sequence(cut)?;
        self.send(original.clone())?;
        *received = Some(self.connection.receive()?.ok_or_else(refused)?);
        // Keep the actual complete typed/raw received owner before postchecks.
        let frame = received.as_ref().ok_or_else(refused)?;
        if !matches!(frame.body, ReceivedBody::Response(_)) {
            return Err(refused());
        }
        original.matches_response(&frame.envelope)?;
        custody.retain_journal_bytes(envelope_bytes(&frame.envelope)?)?;
        custody.controller.get_mut(id).ok_or_else(refused)?.response = Some(frame.envelope.clone());
        self.original_restore_upload_sequence(cut)?;
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original input upload cut or response changed")
}

impl ClientCustody {
    pub(in crate::client) fn has_original_restore_upload_prefix(&self, prefix: &str) -> bool {
        self.controller.keys().any(|id| {
            id.as_str()
                .strip_prefix("cnp-restore-input-")
                .is_some_and(|tail| tail.starts_with(prefix))
        })
    }
}
