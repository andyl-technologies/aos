//! Retains actual bootstrap correlation records after complete physical publication.
//!
//! These private transitions discharge transport credit only. The enclosing
//! publisher must authenticate the exact completed original frame before moving
//! the records; neither a reservation nor this move grants native readiness.

use super::*;

impl CorrelationGuard {
    /// Checks the one original request and its one reserved bootstrap response.
    ///
    /// # Errors
    /// Refuses a fenced guard, changed scope, sequence, record or extra traffic.
    pub(crate) fn original_bootstrap_writing_data(
        &self,
        original: &Envelope,
        response: &Envelope,
    ) -> Result<(), ProviderError> {
        self.check_live()?;
        self.check_scope(original)?;
        self.check_scope(response)?;
        original.matches_response(response)?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        if original.method != Method::NativeImport18Bootstrap
            || original.message != MessageKind::Request
            || response.message != MessageKind::Response
            || original.sequence.get() != 2
            || response.sequence.get() != 2
            || self.next_received != 3
            || self.next_sent != 3
            || !self.pending.is_empty()
            || self.received_requests.len() != 1
            || self.received_requests.get(id) != Some(original)
            || self.writing_responses.len() != 1
            || self.writing_responses.get(id) != Some(response)
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Moves the two actual SDK records into retained custody after exact write.
    ///
    /// The private publisher first proves the complete canonical literal and
    /// physical transfer in its same original stream/journal. Destinations are
    /// installed before any subsequent fallible check; failures keep prefixes.
    ///
    /// # Errors
    /// Refuses occupied destinations, changed current records or unexpected loss.
    pub(crate) fn original_bootstrap_confirm_into_data(
        &mut self,
        original: &Envelope,
        response: &Envelope,
        retained_request: &mut Option<Envelope>,
        retained_response: &mut Option<Envelope>,
    ) -> Result<(), ProviderError> {
        if retained_request.is_some() || retained_response.is_some() {
            return Err(refused());
        }
        self.original_bootstrap_writing_data(original, response)?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        *retained_request = self.received_requests.remove(id);
        *retained_response = self.writing_responses.remove(id);
        if retained_request.is_none() || retained_response.is_none() {
            self.fence();
            return Err(refused());
        }
        Ok(())
    }

    /// Checks current transport settlement against the retained actual records.
    ///
    /// No state is reconstructed or inferred from the announced funding row.
    ///
    /// # Errors
    /// Refuses fenced/foreign records, sequences or any remaining SDK traffic.
    pub(crate) fn original_bootstrap_confirmed_data(
        &self,
        retained_request: &Envelope,
        retained_response: &Envelope,
    ) -> Result<(), ProviderError> {
        self.check_live()?;
        self.check_scope(retained_request)?;
        self.check_scope(retained_response)?;
        retained_request.matches_response(retained_response)?;
        if retained_request.method != Method::NativeImport18Bootstrap
            || retained_request.message != MessageKind::Request
            || retained_response.message != MessageKind::Response
            || retained_request.sequence.get() != 2
            || retained_response.sequence.get() != 2
            || self.next_received != 3
            || self.next_sent != 3
            || !self.pending.is_empty()
            || !self.received_requests.is_empty()
            || !self.writing_responses.is_empty()
        {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original bootstrap response publication")
}
