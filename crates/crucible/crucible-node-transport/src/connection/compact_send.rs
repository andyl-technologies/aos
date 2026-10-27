//! Publishes compact SDK frames without whole-envelope JSON projection copies.
//!
//! Closed validation, strict parsing, literal retention and correlation still
//! precede publication. A failed response write preserves both correlation
//! owners; only a completely published response retires their transport credit.

use super::*;

impl<S: ProviderStream> Connection<S> {
    /// Checks an idle compact boundary without containing revoked authority.
    ///
    /// Funding queries run before admission of incident allocation. Unlike the
    /// operational check below, this read-only check cannot call `contain`.
    ///
    /// # Errors
    /// Refuses foreign, fenced or revoked ownership, pending native responses,
    /// or unresolved correlation in any direction.
    pub(crate) fn authenticate_compact_exchange_idle_data(&self) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.ensure_no_pending_native_restore_response()?;
        if self.fenced {
            return Err(ProviderError::Correlation("connection is fenced"));
        }
        self.authority.ensure_live()?;
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)
    }

    /// Checks the empty correlation boundary around an ordinary compact exchange.
    ///
    /// Historical sequence and journal use need not be empty. The settled-cut
    /// predicate checks all three actual correlation maps and the failure flag;
    /// it grants no capture or Source permission and changes no request credit.
    ///
    /// # Errors
    /// Refuses a fenced or revoked connection, a pending native response, or any
    /// unresolved outgoing request, incoming request or response publication.
    pub(crate) fn authenticate_compact_exchange_idle(&mut self) -> Result<(), ProviderError> {
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)
            .map_err(|_| {
                ProviderError::Conflict("compact exchange has unresolved connection custody")
            })
    }

    pub(crate) fn send_compact(&mut self, envelope: &Envelope) -> Result<(), ProviderError> {
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;

        let limits = self.authority.limits();
        let maximum_bytes = allowance(limits.frame_bytes.get())?;
        let maximum_nesting = allowance(limits.nesting.get())?;
        // A legacy provider reply may exceed today's F, including after its
        // replacement sequence grows. Refuse that complete original before any
        // typed decoder or selected extension codec can allocate from its K.
        crate::client::compact_json::envelope_encoded_bytes(envelope, maximum_bytes)?;
        self.validate_body(envelope, false)?;
        let bytes = crate::client::compact_json::encode_envelope(envelope, maximum_bytes)?;
        canonical::parse_json_with_depth(&bytes, maximum_bytes, maximum_nesting)?;

        let original_slot = self.prepare_original_send(&bytes)?;
        self.retain_original_request_id(envelope, original_slot)?;
        self.authority
            .with_live(|| self.guard.register_outgoing(envelope.clone()))?;
        let result = self.publish_original_send(&bytes, original_slot);
        if result.is_err() {
            self.contain(ConnectionFailure::Write);
        } else if envelope.message == MessageKind::Response
            && let Err(error) = self.guard.confirm_response_sent(envelope)
        {
            self.contain(ConnectionFailure::Protocol);
            return Err(error);
        }
        result
    }
}

#[cfg(test)]
mod tests;
