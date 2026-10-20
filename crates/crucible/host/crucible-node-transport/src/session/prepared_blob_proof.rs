//! Checks one actual pending Blob-proof response before typed body allocation.
//!
//! This borrowed check neither mutates sequence/correlation state nor grants
//! receive credit. The normal typed validator and receive transition still run
//! afterward. Generic incoming request handling remains unchanged.

use super::*;

impl CorrelationGuard {
    pub(crate) fn authenticate_prepared_blob_proof_header(
        &self,
        original: &Envelope,
        received: &Envelope,
    ) -> Result<(), ProviderError> {
        self.check_live()?;
        self.check_scope(received)?;
        if original.message != MessageKind::Request
            || !matches!(
                original.method,
                Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
            )
            || received.message != MessageKind::Response
            || received.sequence.get() != self.next_received
        {
            return Err(ProviderError::Correlation(
                "prepared Blob proof response header",
            ));
        }
        let id = original
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "prepared Blob proof request ID absent",
            ))?;
        if self.pending.get(id) != Some(original) {
            return Err(ProviderError::Correlation(
                "prepared Blob proof pending original differs",
            ));
        }
        original.matches_response(received)
    }
}

impl CorrelationGuard {
    pub(crate) fn preflight_original_packet_prefix_data(
        &self,
        original: &Envelope,
        first: u64,
        outgoing: usize,
        incoming: usize,
    ) -> Result<(), ProviderError> {
        self.check_live()?;
        self.check_scope(original)?;
        let id = original
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "packet prefix original ID absent",
            ))?;
        if original.message != MessageKind::Request
            || self.received_requests.len() != 1
            || self.received_requests.get(id) != Some(original)
            || !self.pending.is_empty()
            || !self.writing_responses.is_empty()
            || self.next_sent != first
            || outgoing
                != incoming
                    .checked_add(1)
                    .ok_or(ProviderError::ResourceExhausted("packet prefix count"))?
            || incoming > self.maximum_requests
        {
            return Err(ProviderError::Correlation(
                "packet prefix original correlation differs",
            ));
        }
        self.preflight_confirmation_sequences(outgoing, incoming)
    }
}
