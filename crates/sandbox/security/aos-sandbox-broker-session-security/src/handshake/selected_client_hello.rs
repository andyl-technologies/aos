//! Retains the selected Client's actual canonical Hello and transcript work.
//!
//! The existing decoder and verifier are the sole engines. This private stage
//! holds their reached models/results through native posts and raw-stage failure.

use super::*;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionTranscriptVerifyCaptureV1, CanonicalBrokerClientHelloV1,
    CanonicalBrokerServerHelloV1, ProtectedBrokerSessionVerificationContextV1,
    verify_broker_session_transcript_retaining_v1,
};
use aos_sandbox_broker_session_protocol::projection::{
    CanonicalBrokerClientHelloDecodeCaptureV1, CanonicalBrokerServerHelloDecodeCaptureV1,
    decode_canonical_client_hello_retaining_v1, decode_canonical_server_hello_retaining_v1,
};

#[derive(Debug, thiserror::Error)]
#[error("selected Hello typed verification remains refused with its original retained")]
struct TypedClosedV1;

pub(super) struct SelectedClientHelloVerificationV1 {
    client_capture: CanonicalBrokerClientHelloDecodeCaptureV1,
    pub(super) client: Option<CanonicalBrokerClientHelloV1>,
    broker_capture: CanonicalBrokerServerHelloDecodeCaptureV1,
    pub(super) broker: Option<CanonicalBrokerServerHelloV1>,
    broker_binding: Option<Result<(), TypedClosedV1>>,
    context: Option<Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError>>,
    pub(super) transcript_capture: BrokerSessionTranscriptVerifyCaptureV1,
    transcript: Option<VerifiedBrokerSessionTranscriptV1>,
    completion: Option<Result<(), TypedClosedV1>>,
    closed: Option<TypedClosedV1>,
    entered: bool,
}

impl SelectedClientHelloVerificationV1 {
    pub(super) fn new() -> Self {
        Self {
            client_capture: CanonicalBrokerClientHelloDecodeCaptureV1::new(),
            client: None,
            broker_capture: CanonicalBrokerServerHelloDecodeCaptureV1::new(),
            broker: None,
            broker_binding: None,
            context: None,
            transcript_capture: BrokerSessionTranscriptVerifyCaptureV1::new(),
            transcript: None,
            completion: None,
            closed: None,
            entered: false,
        }
    }

    pub(super) fn receiving_obligations_v1() -> Option<(usize, usize)> {
        let hello_bytes = CLIENT_HELLO_MAXIMUM_BYTES.checked_add(SERVER_HELLO_MAXIMUM_BYTES)?;
        // Four existing matching Hello-model pairs cover the projection models.
        // Price the actual verification's separate negotiation/artifact backing
        // and constructor temporary here, before the shared fixed admission.
        let bytes = BrokerSessionTranscriptVerifyCaptureV1::receiving_heap_bytes_v1(hello_bytes)?
            .checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?;
        let cells = CanonicalBrokerClientHelloDecodeCaptureV1::receiving_metadata_cells_v1()?
            .checked_add(CanonicalBrokerServerHelloDecodeCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(BrokerSessionTranscriptVerifyCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(BrokerSessionTranscriptVerifyCaptureV1::receiving_table_metadata_cells_v1(hello_bytes)?)?
            .checked_add(11)?;
        Some((bytes, cells))
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.client_capture.failure().map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.broker_capture.failure().map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.broker_binding.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.context.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.transcript_capture.failure().map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.completion.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.closed.as_ref().map(|cause| cause as &dyn std::error::Error))
    }

    pub(super) fn verify_once(
        &mut self,
        client_bytes: &[u8],
        broker_bytes: &[u8],
        broker_process: [u8; 16],
        custody: &mut ClientHandshakeCustodyV1,
    ) -> Result<(), HandshakeError> {
        if self.entered {
            self.closed.get_or_insert(TypedClosedV1);
            return Err(HandshakeError::RemoteInvalid);
        }
        self.entered = true;
        let result = self.verify_inner(client_bytes, broker_bytes, broker_process, custody);
        self.completion = Some(result.as_ref().map(|_| ()).map_err(|_| TypedClosedV1));
        result
    }

    fn verify_inner(
        &mut self,
        client_bytes: &[u8],
        broker_bytes: &[u8],
        broker_process: [u8; 16],
        custody: &mut ClientHandshakeCustodyV1,
    ) -> Result<(), HandshakeError> {
        decode_canonical_client_hello_retaining_v1(client_bytes, &mut self.client_capture)
            .map_err(|_| HandshakeError::RemoteInvalid)?;
        self.client = Some(self.client_capture.take_model_once()
            .map_err(|_| HandshakeError::RemoteInvalid)?);
        decode_canonical_server_hello_retaining_v1(broker_bytes, &mut self.broker_capture)
            .map_err(|_| HandshakeError::RemoteInvalid)?;
        self.broker = Some(self.broker_capture.take_model_once()
            .map_err(|_| HandshakeError::RemoteInvalid)?);
        let client = self.client.as_ref().ok_or(HandshakeError::RemoteInvalid)?;
        let broker = self.broker.as_ref().ok_or(HandshakeError::RemoteInvalid)?;
        self.broker_binding = Some(if broker.signed_artifact().subject().broker_process() == broker_process {
            Ok(())
        } else {
            Err(TypedClosedV1)
        });
        if !matches!(self.broker_binding, Some(Ok(()))) {
            return Err(HandshakeError::RemoteInvalid);
        }
        self.context = Some(custody.context_for_handshake(broker_process));
        let context = match self.context.as_ref() {
            Some(Ok(context)) => context,
            _ => return Err(HandshakeError::Local(custody.poison_handshake_custody())),
        };
        verify_broker_session_transcript_retaining_v1(
            client, broker, context, &mut self.transcript_capture,
        ).map_err(|_| HandshakeError::RemoteInvalid)?;
        self.transcript = Some(self.transcript_capture.take_transcript_once()
            .map_err(|_| HandshakeError::RemoteInvalid)?);
        Ok(())
    }

    pub(super) fn take_transcript_positive_v1(&mut self) -> Option<VerifiedBrokerSessionTranscriptV1> {
        if matches!(self.completion, Some(Ok(()))) && self.failure().is_none() {
            self.transcript.take()
        } else {
            None
        }
    }
}
