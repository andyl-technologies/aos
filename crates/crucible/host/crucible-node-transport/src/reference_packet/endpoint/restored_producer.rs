//! Publishes a fresh recurring Producer original on the same released socket.
//!
//! The actual published-first native witness selects this closed route. A spent
//! ingress owner precedes receive; current model recount and an independent
//! action debit precede proof production. Only complete ACK publication reopens
//! either the endpoint or native ledger. Input and Capture remain refused. The main endpoint selector remains closed until the complete Core/Source/publisher conjunction is installed.

use super::*;
use crate::reference_packet::service::ack_emitter::{
    NativeAckBoot, OriginalRestoredSuffixPostObservation,
};

impl<S: ProviderStream> PacketEndpoint<S> {
    /// Authenticates the actual published-first witness before selected receive.
    ///
    /// # Errors
    /// Refuses failed native custody or changed connection/Control provenance.
    pub(super) fn prepare_original_restored_producer_receive(
        &self,
    ) -> Result<Option<OriginalRestoredSuffixPostObservation>, ProviderError> {
        self.ensure_complete_origin()?;
        let Some(boot) = self.canonical_ack_boot.as_ref() else {
            return Ok(None);
        };
        if !self.native.original_restored_producer_selected_data()
            || !NativeAckBoot::original_restored_suffix_observation_ready_data(boot)?
        {
            return Ok(None);
        }
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        NativeAckBoot::original_restored_suffix_post_observation_data(
            boot,
            connection,
            &self.native,
            &self.records,
        )
        .map(Some)
    }

    /// Publishes one current scheduling proof under independent native debits.
    ///
    /// # Errors
    /// Refuses expired deadlines, malformed traffic, short native credit, changed
    /// proof/currency or incomplete prefix/ACK publication; the endpoint stays held.
    pub(super) fn receive_and_dispatch_original_restored_producer(
        &mut self,
        witness: OriginalRestoredSuffixPostObservation,
        deadline: &crate::client::ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        deadline.remaining()?;
        if !self.held || self.records.len() >= EXCHANGES {
            return Err(refused());
        }
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(refused());
        };
        let frame =
            usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| refused())?;
        let scope = witness.retain_original_producer_ingress_data(
            connection,
            &self.native,
            &self.records,
            frame,
        )?;
        let _ = connection;
        self.reserve()?;
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(refused());
        };
        if !connection.receive_original_restored_producer_data(
            &scope,
            &self.native,
            &self.records,
        )? {
            return Err(ProviderError::Frame(
                "closed Producer lifecycle original peer closed",
            ));
        }
        deadline.remaining()?;
        scope.begin_dispatch_data(connection, &self.native, &self.records)?;
        let original = scope.original_data()?;
        let decoded = crate::bodies::decode_request(original.method, &original.body)?;
        if matches!(
            original.method,
            Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
        ) {
            // Actual BlobReceiver/pins/content mutation is separately funded by
            // this original's spent action row. Retain its real returned reply
            // before prefix construction; a boolean never certifies an upload.
            self.native
                .authenticate_original_restored_producer_upload_data(&original, &scope)?;
            let reply = if let crate::bodies::RequestBody::BlobFinish(finish) = &decoded {
                self.finish_original_restored_producer_upload(&original, finish)?
            } else {
                self.upload(&original, &decoded)?.ok_or_else(refused)?
            };
            scope.retain_prepared_reply_data(&reply)?;
            self.prepare(&original, &reply)?;
        } else {
            let transport = &mut self.transport;
            let sequence = &mut self.next_sequence;
            let credit = &mut self.transport_credit;
            let authority = &self.authority;
            let mut prepare = |reply: &super::super::control::PacketControlReply| {
                // Immediate Begin calls this before its actual socket callback;
                // after mutation the original result must equal this same row.
                scope.retain_prepared_reply_data(reply)?;
                prefix::prepare(transport, sequence, credit, authority, &original, reply)
            };
            self.native
                .dispatch_original_restored_producer_with_preflight(
                    &original,
                    &scope,
                    &mut prepare,
                )?;
        }
        let Some(Transport::Prepared(exchange, acknowledgements)) = self.transport.as_mut() else {
            return Err(refused());
        };
        exchange.publish(&mut |sent, received| acknowledgements.validate(sent, received))?;
        drop(original);
        let Some(Transport::Prepared(exchange, _)) = self.transport.take() else {
            return Err(refused());
        };
        let (connection, record) = exchange.into_parts();
        self.records.push(record);
        self.transport = Some(Transport::Connected(connection));
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        deadline.remaining()?;
        scope.complete_publication_data(connection, &self.native, &self.records)?;
        self.held = false;
        Ok(())
    }
    fn finish_original_restored_producer_upload(
        &mut self,
        envelope: &Envelope,
        finish: &crate::bodies::BlobFinishRequest,
    ) -> Result<super::super::control::PacketControlReply, ProviderError> {
        let verified = self.uploads.finish(&self.key(&finish.transfer_id))?;
        let content = verified.content().clone();
        if content.length.get() > 8192 || content.media_type != "application/json" {
            return Err(refused());
        }
        let schema = self.policy.consuming_schema(&content, envelope)?;
        let owner = envelope.request_id.0.as_ref().ok_or_else(refused)?.clone();
        let verifier = ClosedProducerUpload {
            policy: self.policy.as_ref(),
        };
        let pin = self
            .uploads
            .pin_operation(&verified, owner, schema, &verifier)?;
        pin.with_bytes(|bytes| self.native.install_content(content.clone(), bytes))??;
        self.pins.push(pin);
        Ok(super::super::control::PacketControlReply {
            body: prefix::completed(crate::bodies::BlobFinishResult {
                transfer_id: finish.transfer_id.clone(),
                content,
            })?,
            evidence: Vec::new(),
        })
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("closed Producer lifecycle same released endpoint differs")
}

/// Counts the selected service's concrete Unix-stream publication owners.
pub(crate) fn original_restored_producer_endpoint_counter_scratch_data() -> usize {
    use std::mem::size_of;
    type NativeTransport = Transport<std::os::unix::net::UnixStream>;
    size_of::<ClosedProducerUpload<'static>>()
        + size_of::<Result<super::super::control::PacketControlReply, ProviderError>>()
        + size_of::<serde_json::Value>()
        + size_of::<Result<serde_json::Value, crucible_node_format::ContractError>>()
        + size_of::<crate::blob::VerifiedTransfer>()
        + size_of::<Result<crate::blob::VerifiedTransfer, ProviderError>>()
        + size_of::<crate::blob::OperationContentPin>()
        + size_of::<Result<crate::blob::OperationContentPin, ProviderError>>()
        + size_of::<Result<Result<(), ProviderError>, ProviderError>>()
        + size_of::<OriginalRestoredSuffixPostObservation>()
        + size_of::<Option<OriginalRestoredSuffixPostObservation>>()
        + size_of::<Result<Option<OriginalRestoredSuffixPostObservation>, ProviderError>>()
        + size_of::<
            crate::reference_packet::service::ack_emitter::OriginalRestoredProducerRead<'static>,
        >()
        + size_of::<
            Result<
                crate::reference_packet::service::ack_emitter::OriginalRestoredProducerRead<
                    'static,
                >,
                ProviderError,
            >,
        >()
        + size_of::<NativeTransport>()
        + size_of::<Option<NativeTransport>>()
        + size_of::<&mut Option<NativeTransport>>()
        + size_of::<&mut u64>()
        + size_of::<&mut usize>()
        + size_of::<&ConnectionAuthority>()
        + size_of::<crate::handshake::Limits>()
        + size_of::<&crate::client::ExchangeDeadline>()
        + size_of::<(Connection<std::os::unix::net::UnixStream>, ExchangeRecord)>()
        + size_of::<
            &mut dyn FnMut(&super::super::control::PacketControlReply) -> Result<(), ProviderError>,
        >()
        + size_of::<Result<(), ProviderError>>()
}

// This borrowed verifier narrows the existing actual installed policy. It has
// no alternate schema, key, byte-access path or admission constructor.
struct ClosedProducerUpload<'a> {
    policy: &'a dyn PacketEndpointPolicy,
}
impl crate::blob::BlobSchemaVerifier for ClosedProducerUpload<'_> {
    fn verify_schema(
        &self,
        schema: &ContentRef,
        content: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        if bytes.len() > 8192 || content.media_type != "application/json" {
            return Err(refused());
        }
        let value = crucible_node_format::canonical::parse_json(bytes, 8192)?;
        authenticate_closed_upload_value(&value)?;
        self.policy.verify_schema(schema, content, bytes)
    }
}

fn authenticate_closed_upload_value(value: &serde_json::Value) -> Result<(), ProviderError> {
    match value.get("schema").and_then(serde_json::Value::as_str) {
        Some("source-owned.packet-common-grant.v5") => {
            if value.get("input") != Some(&serde_json::Value::Null)
                || value
                    .get("input_watermark")
                    .and_then(serde_json::Value::as_str)
                    != Some("0")
            {
                return Err(refused());
            }
        }
        Some("source-owned.packet-consumption.v1") => {
            if value
                .get("outputs")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|outputs| outputs.len() > 1)
            {
                return Err(refused());
            }
        }
        _ => return Err(refused()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_upload_header_refuses_input_and_unrelated_schema_before_policy() {
        let mut grant = serde_json::json!({"schema":"source-owned.packet-common-grant.v5", "input":null, "input_watermark":"0"});
        authenticate_closed_upload_value(&grant).unwrap();
        grant["input"] = serde_json::json!({"cut":[]});
        assert!(authenticate_closed_upload_value(&grant).is_err());
        assert!(
            authenticate_closed_upload_value(
                &serde_json::json!({"schema":"crucible/coordinator-initial/1"})
            )
            .is_err()
        );
        assert!(authenticate_closed_upload_value(&serde_json::json!({"schema":"source-owned.packet-consumption.v1", "outputs":["a","b"]})).is_err());
    }
}
