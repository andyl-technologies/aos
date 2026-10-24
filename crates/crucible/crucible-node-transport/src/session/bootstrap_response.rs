//! Settles the original Source bootstrap response without dropping SDK custody.
//!
//! The defining Source exchange admits and retains the destination before entry.
//! These transitions move the actual pending request; they authenticate transport
//! correlation only. The same Source still verifies its independently retained
//! context and receipt MAC before issuing any bootstrap completion witness.

use super::*;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF, NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT,
};

impl CorrelationGuard {
    /// Checks the sole sequence-two bootstrap request before response settlement.
    ///
    /// The closed body, proof MAC, original literal, negotiated feature and live
    /// Source occurrence are separate caller checks. No allocation runs here.
    ///
    /// # Errors
    /// Refuses fenced or imported state, another original, scope, extension
    /// position or unrelated traffic.
    pub fn original_bootstrap_pending_data(
        &self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.check_live()?;
        self.check_scope(original)?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        if !bootstrap_header_data(original, MessageKind::Request)
            || self.continuation_installed
            || self.next_received != 2
            || self.next_sent != 3
            || self.pending.len() != 1
            || self.pending.get(id) != Some(original)
            || !self.received_requests.is_empty()
            || !self.writing_responses.is_empty()
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Moves the actual pending original into the retained Source exchange.
    ///
    /// The caller retains its independently decoded response before entry. An
    /// occupied destination refuses before beginning a receive; every later
    /// refusal fences the guard and preserves whichever owner holds the request.
    /// A successful move advances incoming transport sequence exactly once.
    ///
    /// # Errors
    /// Refuses occupied output, changed original/response or transport state.
    pub fn original_bootstrap_receive_into_data(
        &mut self,
        original: &Envelope,
        response: &Envelope,
        retained_request: &mut Option<Envelope>,
    ) -> Result<(), ProviderError> {
        if retained_request.is_some() {
            return Err(refused());
        }
        let result = (|| {
            self.original_bootstrap_pending_data(original)?;
            self.check_scope(response)?;
            original.matches_response(response)?;
            if !bootstrap_header_data(response, MessageKind::Response) {
                return Err(refused());
            }

            let id = original.request_id.0.as_ref().ok_or_else(refused)?;
            *retained_request = self.pending.remove(id);
            // Install the moved record before the first subsequent fallible
            // check. Failure may fence transport but cannot discard this owner.
            let retained = retained_request.as_ref().ok_or_else(refused)?;
            self.next_received = 3;
            self.original_bootstrap_received_data(retained, response)
        })();
        if result.is_err() {
            self.fence();
        }
        result
    }

    /// Checks current settlement beside the retained original and response.
    ///
    /// This borrowed DATA check neither reconstructs an old pending request nor
    /// verifies the Source receipt MAC or grants a subsequent native phase.
    /// It cannot prove that caller-supplied historical records are genuine owners.
    ///
    /// # Errors
    /// Refuses fenced/imported state, changed scope, sequence or remaining credit.
    pub fn original_bootstrap_received_data(
        &self,
        retained_request: &Envelope,
        response: &Envelope,
    ) -> Result<(), ProviderError> {
        self.check_live()?;
        self.check_scope(retained_request)?;
        self.check_scope(response)?;
        retained_request.matches_response(response)?;
        if !bootstrap_header_data(retained_request, MessageKind::Request)
            || !bootstrap_header_data(response, MessageKind::Response)
            || self.continuation_installed
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

    /// Names fixed borrowed controls for the dedicated request move and checks.
    ///
    /// The caller separately funds the actual retained Envelope, nested metadata
    /// comparison depth and closed body/proof/receipt decoders before entry.
    pub fn original_bootstrap_receive_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<[&Envelope; 3]>()
            + size_of::<&mut Option<Envelope>>()
            + size_of::<&Id>()
            + size_of::<Option<&Id>>()
            + size_of::<Option<&Envelope>>()
            + size_of::<Result<&Envelope, ProviderError>>()
            + size_of::<MessageKind>()
            + size_of::<&str>()
            + size_of::<bool>()
            + size_of::<[Result<(), ProviderError>; 5]>()
    }
}

fn bootstrap_header_data(envelope: &Envelope, message: MessageKind) -> bool {
    let extension = match message {
        MessageKind::Request => NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF,
        MessageKind::Response => NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT,
        MessageKind::Event => return false,
    };
    envelope.message == message
        && envelope.method == Method::NativeImport18Bootstrap
        && envelope.sequence.get() == 2
        && envelope.extensions.len() == 1
        && envelope.extensions.contains_key(extension)
        && envelope.request_id.0.is_some()
        && envelope.node_id.0.is_none()
        && envelope.execution_owner_id.0.is_none()
        && envelope.capture_owner_id.0.is_none()
        && envelope.operation_id.0.is_none()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original Source bootstrap response settlement")
}

#[cfg(test)]
#[path = "bootstrap_response/tests.rs"]
mod tests;
