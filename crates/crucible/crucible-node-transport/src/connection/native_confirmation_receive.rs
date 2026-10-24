//! Restricts the quoted confirmation receive before allocating a typed body.
//!
//! The current completed report owner, same Capture terminal record and original
//! bank remain borrowed arguments. No persistent receive mode is installed.

use super::*;
use crate::protocol_snapshot::ProtocolCaptureCut;

fn refusal() -> ProviderError {
    ProviderError::Correlation("quoted Capture confirmation header differs")
}

fn authenticate_header(
    capture: &Envelope,
    terminal: &Envelope,
    poll: &Envelope,
) -> Result<(), ProviderError> {
    if capture.message != MessageKind::Request
        || capture.method != Method::Begin
        || capture.body.get("kind").and_then(serde_json::Value::as_str) != Some("capture")
        || terminal
            .body
            .get("status")
            .and_then(serde_json::Value::as_str)
            != Some("completed")
        || terminal
            .body
            .get("operation_state")
            .and_then(serde_json::Value::as_str)
            != Some("completed")
        || poll.message != MessageKind::Request
        || poll.method != Method::Poll
        || poll.protocol != capture.protocol
        || poll.session_id != capture.session_id
        || poll.incarnation_id != capture.incarnation_id
        || poll.node_id != capture.node_id
        || poll.capture_owner_id != capture.capture_owner_id
        || poll.operation_id != capture.operation_id
        || poll.execution_owner_id.0.is_some()
        || poll.request_id.0.is_none()
        || poll.request_id == capture.request_id
        || poll.body.len() != 2
        || poll
            .body
            .get("after_observation_sequence")
            .and_then(serde_json::Value::as_str)
            != Some("0")
    {
        return Err(refusal());
    }
    capture.matches_response(terminal)?;
    let projection = ConfirmationProjection::from_envelope(poll)?;
    if projection.after.is_some()
        || projection
            .capture
            .get("capture_request_id")
            .and_then(serde_json::Value::as_str)
            != capture.request_id.0.as_ref().map(|id| id.as_str())
        || projection
            .capture
            .get("capture_terminal_sequence")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<u64>().ok())
            != Some(terminal.sequence.get())
    {
        return Err(refusal());
    }
    // Full original hashes/refs and actual after issuance are independently
    // checked by the endpoint before any confirmation publication.
    Ok(())
}

impl Connection<crate::client::DeadlineStream> {
    pub(crate) fn receive_original_native_confirmation_after_capture(
        &mut self,
        quote: &super::native_capture_quote::NativeCaptureSdkCompletedQuote,
        capture: &Envelope,
        terminal_record: &ExchangeRecord,
        blobs: &crate::blob::BlobReceiver,
        context: &crate::reference_packet::service::OriginalNativeCaptureContext<'_>,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        quote.authenticate_same_target_data(self, blobs, context)?;
        self.authenticate_native5_source_codec()?;
        self.original_native_owned11_admission()?;
        self.ensure_no_pending_native_restore_response()?;
        self.guard.protocol_cut(ProtocolCaptureCut::HostSettled)?;
        if self.role != EndpointRole::Provider
            || terminal_record.sent() != terminal_record.originals().len()
        {
            return Err(refusal());
        }
        let index = terminal_record
            .originals()
            .len()
            .checked_sub(1)
            .ok_or_else(refusal)?;
        {
            let terminal = terminal_record.original_sent_frame(self, index)?;
            capture.matches_response(terminal.original())?;
            if terminal
                .original()
                .body
                .get("status")
                .and_then(serde_json::Value::as_str)
                != Some("completed")
            {
                return Err(refusal());
            }
        }
        self.check_authority()?;
        let result = self
            .receive_confirmation_inner(capture, &terminal_record.originals()[index])
            .and_then(|received| {
                if received.is_some() {
                    quote.authenticate_same_target_data(self, blobs, context)?;
                }
                Ok(received)
            });
        match &result {
            Ok(None) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }

    fn receive_confirmation_inner(
        &mut self,
        capture: &Envelope,
        terminal: &Envelope,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        let Some(value) = self.reader.read()? else {
            return Ok(None);
        };
        let envelope: Envelope =
            serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
        authenticate_header(capture, terminal, &envelope)?;
        // This borrowed selection/grammar check precedes typed Poll copies.
        self.native5_codec
            .as_ref()
            .ok_or_else(refusal)?
            .authenticate_confirmation_selection(&self.authority)?;
        let body = self.validate_body(&envelope, true)?;
        self.retain_original_request_id(&envelope, self.reader.original_slot())?;
        self.authority.with_live(|| self.guard.receive(&envelope))?;
        self.authenticate_native5_confirmation_poll(&envelope)?;
        Ok(Some(ReceivedFrame { envelope, body }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Nullable;
    use crate::reference_packet::service::confirmation::{
        PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION, PacketNativeAfterConfirmationRequest,
    };
    use crucible_node_format::{Extensions, U64, canonical};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn data() -> Result<(Envelope, Envelope, Envelope), Box<dyn std::error::Error>> {
        let capture = Envelope {
            protocol: "CNP/1".to_owned(),
            message: MessageKind::Request,
            session_id: Nullable(Some(Id::new("session")?)),
            incarnation_id: Nullable(Some(Id::new("incarnation")?)),
            node_id: Nullable(Some(Id::new("node")?)),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(Some(Id::new("capture-owner")?)),
            request_id: Nullable(Some(Id::new("capture-request")?)),
            operation_id: Nullable(Some(Id::new("capture-operation")?)),
            sequence: U64::new(20),
            method: Method::Begin,
            body: serde_json::from_value(serde_json::json!({"kind":"capture"}))?,
            extensions: Extensions::new(),
        };
        let mut terminal = capture.clone();
        terminal.message = MessageKind::Response;
        terminal.sequence = U64::new(31);
        terminal.body = serde_json::from_value(serde_json::json!({
            "status":"completed","operation_state":"completed","result":{},"extensions":{}
        }))?;
        let context = PacketNativeAfterConfirmationRequest {
            schema: "source-owned.packet-native-after-confirmation-request/5".to_owned(),
            capture_request_id: Id::new("capture-request")?,
            capture_request_hash: canonical::hash("cnp.request.v1", b"capture")?,
            capture_operation_id: Id::new("capture-operation")?,
            capture_terminal_hash: canonical::hash(
                "source-owned.packet-native-capture-terminal/5",
                b"terminal",
            )?,
            capture_terminal_sequence: terminal.sequence,
            native_snapshot_ref: canonical::content_ref(b"snapshot", "application/json")?,
            native_control_ref: canonical::content_ref(b"control", "application/json")?,
            native_anchor_ref: canonical::content_ref(b"anchor", "application/json")?,
        };
        let mut poll = capture.clone();
        poll.method = Method::Poll;
        poll.sequence = U64::new(32);
        poll.request_id = Nullable(Some(Id::new("confirmation")?));
        poll.body = serde_json::from_value(
            serde_json::json!({"after_observation_sequence":"0","extensions":{}}),
        )?;
        poll.extensions.insert(
            PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION.to_owned(),
            serde_json::to_value(context)?,
        );
        Ok((capture, terminal, poll))
    }

    #[test]
    fn exact_capture_confirmation_header_passes_without_typed_body_decode() -> TestResult {
        let (capture, terminal, poll) = data()?;
        authenticate_header(&capture, &terminal, &poll)?;
        Ok(())
    }

    #[test]
    fn other_method_response_kind_scope_and_extension_refuse_before_typed_body() -> TestResult {
        let (capture, terminal, poll) = data()?;
        let mut changed = poll.clone();
        changed.method = Method::Begin;
        assert!(authenticate_header(&capture, &terminal, &changed).is_err());
        changed = poll.clone();
        changed.message = MessageKind::Response;
        assert!(authenticate_header(&capture, &terminal, &changed).is_err());
        changed = poll.clone();
        changed.session_id = Nullable(Some(Id::new("foreign-session")?));
        assert!(authenticate_header(&capture, &terminal, &changed).is_err());
        changed = poll.clone();
        changed
            .extensions
            .insert("unselected".to_owned(), serde_json::Value::Null);
        assert!(authenticate_header(&capture, &terminal, &changed).is_err());
        changed = poll;
        changed
            .body
            .insert("unselected".to_owned(), serde_json::Value::Null);
        assert!(authenticate_header(&capture, &terminal, &changed).is_err());
        Ok(())
    }
}
