//! Retains one pure transcript verification and its reached negotiation inputs.
//!
//! Ordinary callers consume this destination immediately. Selected callers
//! retain failed partial tables and canonical signed artifact buffers; no
//! constructor establishes live-session or protected-writer authority.

use super::*;
use crate::profile::NegotiationCapture;

/// Retains the actual negotiation, canonical buffers and transcript outcome.
#[doc(hidden)]
pub struct BrokerSessionTranscriptVerifyCaptureV1 {
    negotiation_capture: Option<NegotiationCapture>,
    pub(super) negotiation: Option<ValidatedBrokerSessionNegotiationV1>,
    client_signature: crate::artifact::BrokerSessionArtifactVerifyCaptureV1,
    broker_signature: crate::artifact::BrokerSessionArtifactVerifyCaptureV1,
    client_digest_bytes: Option<Vec<u8>>,
    client_binding_bytes: Option<Vec<u8>>,
    broker_binding_bytes: Option<Vec<u8>>,
    pub(super) result: Option<Result<Option<VerifiedBrokerSessionTranscriptV1>, BrokerSessionTranscriptError>>,
    closed: Option<BrokerSessionTranscriptError>,
    retained: bool,
    entered: bool,
}

impl Default for BrokerSessionTranscriptVerifyCaptureV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerSessionTranscriptVerifyCaptureV1 {
    /// Prearms empty nonauthorizing verification slots without allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            negotiation_capture: None,
            negotiation: None,
            client_signature: crate::artifact::BrokerSessionArtifactVerifyCaptureV1::new(),
            broker_signature: crate::artifact::BrokerSessionArtifactVerifyCaptureV1::new(),
            client_digest_bytes: None,
            client_binding_bytes: None,
            broker_binding_bytes: None,
            result: None,
            closed: None,
            retained: true,
            entered: false,
        }
    }

    pub(super) fn ordinary() -> Self {
        Self { retained: false, ..Self::new() }
    }

    /// Borrows the original deepest reached failure before any reentry marker.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.negotiation_capture.as_ref().and_then(NegotiationCapture::failure)
            .or_else(|| self.client_signature.failure().map(|e| e as &(dyn std::error::Error + Send + Sync)))
            .or_else(|| self.broker_signature.failure().map(|e| e as &(dyn std::error::Error + Send + Sync)))
            .or_else(|| self.result.as_ref().and_then(|r| r.as_ref().err())
                .map(|e| e as &(dyn std::error::Error + Send + Sync)))
            .or_else(|| self.closed.as_ref().map(|e| e as &(dyn std::error::Error + Send + Sync)))
    }

    /// Borrows the complete verified transcript as nonauthorizing DATA.
    #[must_use]
    pub fn transcript(&self) -> Option<&VerifiedBrokerSessionTranscriptV1> {
        self.result.as_ref()?.as_ref().ok()?.as_ref()
    }

    /// Moves the verified transcript once without cloning its feature tables.
    ///
    /// # Errors
    /// Refuses incomplete, failed, repeated or already-consumed verification.
    pub fn take_transcript_once(&mut self)
        -> Result<VerifiedBrokerSessionTranscriptV1, BrokerSessionTranscriptError>
    {
        if self.failure().is_none() {
            if let Some(value) = self.result.as_mut().and_then(|r| r.as_mut().ok()).and_then(Option::take) {
                return Ok(value);
            }
        }
        self.closed.get_or_insert(BrokerSessionTranscriptError::CrossLink);
        Err(BrokerSessionTranscriptError::CrossLink)
    }

    /// Reports the concrete fixed destination layout, including all result slots.
    #[must_use]
    pub const fn inline_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Bounds owned negotiation backing and fixed signed-artifact scratch.
    ///
    /// `encoded_hello_bytes` is the sum of the same two retained wire extents.
    /// Decoded protobuf models belong to the enclosing projection captures and
    /// are excluded here. No public budget or authority follows from this DATA.
    #[must_use]
    pub fn receiving_heap_bytes_v1(encoded_hello_bytes: usize) -> Option<usize> {
        let signed = crate::model::SIGNED_CLIENT_HELLO_BYTES.checked_mul(2)?
            .checked_add(crate::model::SIGNED_BROKER_HELLO_BYTES)?;
        let subject_temporaries = crate::model::CLIENT_HELLO_SUBJECT_BYTES
            .checked_add(crate::model::BROKER_HELLO_SUBJECT_BYTES)?;
        NegotiationCapture::receiving_heap_bytes_v1(encoded_hello_bytes)?
            .checked_add(crate::artifact::BrokerSessionArtifactVerifyCaptureV1::receiving_heap_bytes_v1()?.checked_mul(2)?)?
            .checked_add(signed)?.checked_add(subject_temporaries)?
            // Protected-context digest streams four temporary 120-byte signer
            // encodings. Counting all four is conservative for its fold.
            .checked_add(4 * crate::model::BROKER_SESSION_SIGNER_REFERENCE_BYTES)
    }

    /// Counts all eleven parent fields plus nested negotiation/signature controls.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        NegotiationCapture::receiving_metadata_cells_v1()?
            .checked_add(crate::artifact::BrokerSessionArtifactVerifyCaptureV1::receiving_metadata_cells_v1()?.checked_mul(2)?)?
            .checked_add(11)
    }

    /// Bounds reached negotiation rows and their owned namespace allocations.
    #[must_use]
    pub fn receiving_table_metadata_cells_v1(encoded_hello_bytes: usize) -> Option<usize> {
        NegotiationCapture::receiving_table_metadata_cells_v1(encoded_hello_bytes)
    }

    pub(super) fn capture_once(
        &mut self, client: &CanonicalBrokerClientHelloV1,
        broker: &CanonicalBrokerServerHelloV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<(), BrokerSessionTranscriptError> {
        if self.entered {
            self.closed.get_or_insert(BrokerSessionTranscriptError::CrossLink);
            return Err(BrokerSessionTranscriptError::CrossLink);
        }
        self.entered = true;
        self.result = Some(self.verify_inner(client, broker, context).map(Some));
        if let Some(Err(error)) = &self.result {
            return Err(error.clone());
        }
        Ok(())
    }

    fn verify_inner(
        &mut self, client: &CanonicalBrokerClientHelloV1,
        broker: &CanonicalBrokerServerHelloV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<VerifiedBrokerSessionTranscriptV1, BrokerSessionTranscriptError> {
        context.require_all_active()?;
        if self.retained {
            self.negotiation_capture = Some(NegotiationCapture::new());
            let captured = self.negotiation_capture.as_mut().ok_or(BrokerSessionTranscriptError::CrossLink)?;
            captured.capture(client.message(), broker.message(), context.protocol(),
                context.protocol_major(), context.protocol_minor(), context.audience());
            self.negotiation = Some(captured.take()?);
        } else {
            self.negotiation = Some(validate_authenticated_negotiation_v1(
                client.message(), broker.message(), context.protocol(),
                context.protocol_major(), context.protocol_minor(), context.audience(),
            )?);
        }
        require_client_context(client, context)?;
        let client_key = context.key(BrokerSessionKeyUsageV1::ClientHello);
        client_key.matches_active(client.signed_artifact().signer())?;
        if self.retained {
            client.signed_artifact().verify_with_public_key_retaining_v1(
                client_key.public_key(), &mut self.client_signature,
            )?;
        } else {
            client.signed_artifact().verify_with_public_key(client_key.public_key())?;
        }
        self.verify_remaining(client, broker, context)
    }

    pub(super) fn into_ordinary_result(mut self)
        -> Result<VerifiedBrokerSessionTranscriptV1, BrokerSessionTranscriptError>
    {
        // Canonical binding buffers are already disposed at their old hash
        // boundary. The negotiation local remains the last ordinary owner.
        if self.result.as_ref().is_some_and(Result::is_err) {
            if let Some(Err(error)) = self.result.take() {
                drop(self.negotiation.take());
                return Err(error);
            }
        }
        self.take_transcript_once()
    }

    pub(super) fn verify_remaining(
        &mut self, client: &CanonicalBrokerClientHelloV1,
        broker: &CanonicalBrokerServerHelloV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<VerifiedBrokerSessionTranscriptV1, BrokerSessionTranscriptError> {
        let protected_context_digest = context.protected_context_digest();
        let client_subject = client.signed_artifact().subject();
        let client_digest = if self.retained {
            self.client_digest_bytes = Some(client.signed_artifact().to_canonical_bytes());
            crate::artifact::complete_signed_client_hello_digest_from_canonical_v1(
                self.client_digest_bytes.as_deref().ok_or(BrokerSessionTranscriptError::CrossLink)?,
            )
        } else {
            complete_signed_client_hello_digest_v1(client.signed_artifact())
        };
        let broker_subject = broker.signed_artifact().subject();
        if broker_subject.node_id != context.node_id()
            || broker_subject.boot_id != context.boot_id()
            || broker_subject.protocol != context.protocol()
            || broker_subject.major != context.protocol_major()
            || broker_subject.minor != context.protocol_minor()
            || broker_subject.audience != context.audience()
            || broker_subject.broker_process() != context.broker_process()
            || broker_subject.protected_context_digest() != protected_context_digest
            || broker_subject.cleared_fields_digest() != broker.cleared_fields_digest()
            || broker.message().protocol_major != u32::from(context.protocol_major())
            || broker.message().protocol_minor != u32::from(context.protocol_minor())
            || broker_subject.signed_client_hello_digest() != client_digest
        {
            return Err(BrokerSessionTranscriptError::ContextMismatch);
        }
        if client_subject.nonce() == broker_subject.nonce() {
            return Err(BrokerSessionTranscriptError::EqualNonces);
        }
        let broker_key = context.key(BrokerSessionKeyUsageV1::BrokerHello);
        broker_key.matches_active(broker.signed_artifact().signer())?;
        if self.retained {
            broker.signed_artifact().verify_with_public_key_retaining_v1(
                broker_key.public_key(), &mut self.broker_signature,
            )?;
        } else {
            broker.signed_artifact().verify_with_public_key(broker_key.public_key())?;
        }

        self.client_binding_bytes = Some(client.signed_artifact().to_canonical_bytes());
        self.broker_binding_bytes = Some(broker.signed_artifact().to_canonical_bytes());
        let session_binding = session_binding(
            self.client_binding_bytes.as_deref().ok_or(BrokerSessionTranscriptError::CrossLink)?,
            self.broker_binding_bytes.as_deref().ok_or(BrokerSessionTranscriptError::CrossLink)?,
        );
        // Both canonical binding temporaries ended at this complete pure hash.
        drop(self.broker_binding_bytes.take());
        drop(self.client_binding_bytes.take());
        let negotiation = self.negotiation.take().ok_or(BrokerSessionTranscriptError::CrossLink)?;
        let transcript = VerifiedBrokerSessionTranscriptV1 {
            session_binding,
            protected_context_digest,
            protocol: negotiation.protocol,
            protocol_major: negotiation.major,
            protocol_minor: negotiation.minor,
            audience: negotiation.audience,
            client_process: context.client_process(),
            broker_process: context.broker_process(),
            required_features: negotiation.required_features,
            advertised_features: negotiation.advertised_features,
            required_methods: negotiation.required_methods,
            advertised_methods: negotiation.advertised_methods,
            negotiated_maximum_request_bytes: negotiation.maximum_request_bytes,
            negotiated_maximum_response_bytes: negotiation.maximum_response_bytes,
            phase: BrokerSessionTranscriptPhaseV1::Provisional,
        };
        drop(self.client_digest_bytes.take());
        Ok(transcript)
    }
}
