//! Owns reached historical checkpoint parsing, verification and encoding.
//!
//! These inert destinations retain pure DATA and original causes. They grant
//! no current session, protected writer, financial budget or effect authority.

use super::*;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionContextCheckpointDecodeCaptureV1,
    BrokerSessionTranscriptVerifyCaptureV1,
    CanonicalBrokerClientHelloV1, CanonicalBrokerServerHelloV1,
    verify_broker_session_transcript_retaining_v1,
};
use aos_sandbox_broker_session_protocol::projection::{
    CanonicalBrokerClientHelloDecodeCaptureV1, CanonicalBrokerServerHelloDecodeCaptureV1,
    decode_canonical_client_hello_retaining_v1, decode_canonical_server_hello_retaining_v1,
};

type Cause = dyn std::error::Error + Send + Sync + 'static;

/// Retains reached canonical hellos, negotiation and the actual verify outcome.
#[doc(hidden)]
pub struct HistoricalSessionCheckpointVerifyCaptureV1 {
    client_capture: CanonicalBrokerClientHelloDecodeCaptureV1,
    broker_capture: CanonicalBrokerServerHelloDecodeCaptureV1,
    client: Option<CanonicalBrokerClientHelloV1>,
    broker: Option<CanonicalBrokerServerHelloV1>,
    transcript_capture: BrokerSessionTranscriptVerifyCaptureV1,
    transcript: Option<VerifiedBrokerSessionTranscriptV1>,
    completion: Option<Result<(), HistoricalCheckpointErrorV1>>,
    closed: Option<HistoricalCheckpointErrorV1>,
    retained: bool,
    entered: bool,
}

impl Default for HistoricalSessionCheckpointVerifyCaptureV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl HistoricalSessionCheckpointVerifyCaptureV1 {
    /// Prearms one fixed verification destination without allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client_capture: CanonicalBrokerClientHelloDecodeCaptureV1::new(),
            broker_capture: CanonicalBrokerServerHelloDecodeCaptureV1::new(),
            client: None,
            broker: None,
            transcript_capture: BrokerSessionTranscriptVerifyCaptureV1::new(),
            transcript: None,
            completion: None,
            closed: None,
            retained: true,
            entered: false,
        }
    }

    /// Reports one additional reached constructor/move carrier outside a resident field.
    #[must_use]
    pub const fn construction_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    pub(super) fn ordinary() -> Self {
        Self { retained: false, ..Self::new() }
    }

    /// Borrows the actual earliest nested refusal before the coarse marker.
    #[must_use]
    pub fn failure(&self) -> Option<&Cause> {
        self.client_capture.failure().map(|e| e as &Cause)
            .or_else(|| self.broker_capture.failure().map(|e| e as &Cause))
            .or_else(|| self.transcript_capture.failure())
            .or_else(|| self.completion.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &Cause))
            .or_else(|| self.closed.as_ref().map(|e| e as &Cause))
    }

    /// Borrows a complete verified transcript as nonauthorizing DATA.
    #[must_use]
    pub fn transcript(&self) -> Option<&VerifiedBrokerSessionTranscriptV1> {
        self.transcript.as_ref()
    }

    /// Moves a verified transcript once without copying its owned tables.
    ///
    /// # Errors
    /// Rejects failure, incomplete verification, reentry or an already-taken model.
    pub fn take_transcript_once(&mut self)
        -> Result<VerifiedBrokerSessionTranscriptV1, HistoricalCheckpointErrorV1>
    {
        if self.failure().is_none() && matches!(self.completion, Some(Ok(()))) {
            if let Some(value) = self.transcript.take() {
                return Ok(value);
            }
        }
        self.closed.get_or_insert(HistoricalCheckpointErrorV1::Invalid);
        Err(HistoricalCheckpointErrorV1::Invalid)
    }

    /// Reports the actual fixed capture layout, with embedded nested slots.
    #[must_use]
    pub const fn inline_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Bounds additional negotiation/signature storage beyond Hello projections.
    ///
    /// The enclosing supplier separately prices the two actual decoded Hello
    /// model/parser frontiers. This method never substitutes a maximum model
    /// for each byte or for every historical checkpoint in the journal.
    #[must_use]
    pub fn receiving_nonprojection_heap_bytes_v1(encoded_hello_bytes: usize) -> Option<usize> {
        BrokerSessionTranscriptVerifyCaptureV1::receiving_heap_bytes_v1(encoded_hello_bytes)
    }

    /// Counts all ten parent fields plus both projections and transcript controls.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        CanonicalBrokerClientHelloDecodeCaptureV1::receiving_metadata_cells_v1()?
            .checked_add(CanonicalBrokerServerHelloDecodeCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(BrokerSessionTranscriptVerifyCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(10)
    }

    /// Bounds reached negotiation row and namespace cells beyond projections.
    #[must_use]
    pub fn receiving_table_metadata_cells_v1(encoded_hello_bytes: usize) -> Option<usize> {
        BrokerSessionTranscriptVerifyCaptureV1::receiving_table_metadata_cells_v1(encoded_hello_bytes)
    }

    pub(super) fn capture_once(&mut self, checkpoint: &HistoricalSessionCheckpointV1)
        -> Result<(), HistoricalCheckpointErrorV1>
    {
        if self.entered {
            self.closed.get_or_insert(HistoricalCheckpointErrorV1::Invalid);
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        self.entered = true;
        self.completion = Some(self.verify_inner(checkpoint));
        self.completion.as_ref().ok_or(HistoricalCheckpointErrorV1::Invalid)?.as_ref()
            .map(|_| ()).map_err(|e| *e)
    }

    fn verify_inner(&mut self, checkpoint: &HistoricalSessionCheckpointV1)
        -> Result<(), HistoricalCheckpointErrorV1>
    {
        if self.retained {
            decode_canonical_client_hello_retaining_v1(&checkpoint.client_hello, &mut self.client_capture)
                .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
            self.client = Some(self.client_capture.take_model_once()
                .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?);
            decode_canonical_server_hello_retaining_v1(&checkpoint.broker_hello, &mut self.broker_capture)
                .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
            self.broker = Some(self.broker_capture.take_model_once()
                .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?);
        } else {
            self.client = Some(decode_canonical_client_hello_v1(&checkpoint.client_hello)
                .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?);
            self.broker = Some(decode_canonical_server_hello_v1(&checkpoint.broker_hello)
                .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?);
        }
        let client = self.client.as_ref().ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        let broker = self.broker.as_ref().ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        self.transcript = Some(if self.retained {
            verify_broker_session_transcript_retaining_v1(client, broker, &checkpoint.context,
                &mut self.transcript_capture).map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
            self.transcript_capture.take_transcript_once().map_err(|_| HistoricalCheckpointErrorV1::Invalid)?
        } else {
            verify_broker_session_transcript_v1(client, broker, &checkpoint.context)
                .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?
        });
        self.dispose_successful_inputs();
        Ok(())
    }

    fn dispose_successful_inputs(&mut self) {
        // The verified output owns its own negotiation tables. Both decoded
        // hellos reached the original final borrower at complete verification.
        drop(self.broker.take());
        drop(self.client.take());
    }

    pub(super) fn into_ordinary_result(mut self)
        -> Result<VerifiedBrokerSessionTranscriptV1, HistoricalCheckpointErrorV1>
    {
        if self.failure().is_some() {
            drop(self.broker.take());
            drop(self.client.take());
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        self.take_transcript_once()
    }
}

/// Retains canonical context and checkpoint output bytes before later refusal.
#[doc(hidden)]
pub struct HistoricalSessionCheckpointEncodeCaptureV1 {
    context: Option<Vec<u8>>,
    encoded: Option<Vec<u8>>,
    completion: Option<Result<(), HistoricalCheckpointErrorV1>>,
    closed: Option<HistoricalCheckpointErrorV1>,
    entered: bool,
}

impl Default for HistoricalSessionCheckpointEncodeCaptureV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl HistoricalSessionCheckpointEncodeCaptureV1 {
    /// Prearms fixed empty encoding slots without allocating.
    #[must_use]
    pub fn new() -> Self {
        Self { context: None, encoded: None, completion: None, closed: None, entered: false }
    }

    /// Borrows the exact encoding refusal before a reentry marker.
    #[must_use]
    pub fn failure(&self) -> Option<&Cause> {
        self.completion.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &Cause)
            .or_else(|| self.closed.as_ref().map(|e| e as &Cause))
    }

    /// Borrows only a complete canonical checkpoint encoding.
    #[must_use]
    pub fn encoded(&self) -> Option<&[u8]> {
        matches!(self.completion, Some(Ok(()))).then_some(())?;
        self.encoded.as_deref()
    }

    /// Moves complete encoded bytes once, preserving the returned outcome.
    ///
    /// # Errors
    /// Rejects incomplete, failed, repeated or already-consumed encoding.
    pub fn take_encoded_once(&mut self) -> Result<Vec<u8>, HistoricalCheckpointErrorV1> {
        if self.failure().is_none() && matches!(self.completion, Some(Ok(()))) {
            if let Some(value) = self.encoded.take() {
                return Ok(value);
            }
        }
        self.closed.get_or_insert(HistoricalCheckpointErrorV1::Invalid);
        Err(HistoricalCheckpointErrorV1::Invalid)
    }

    /// Reports the concrete fixed encoder destination layout.
    #[must_use]
    pub const fn inline_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Bounds one exact context buffer and the complete checkpoint output.
    #[must_use]
    pub fn receiving_heap_bytes_v1(encoded_hello_bytes: usize) -> Option<usize> {
        let context = ProtectedBrokerSessionVerificationContextV1::checkpoint_encoded_bytes_v1();
        context.checked_mul(2)?.checked_add(HEADER_BYTES)?
            .checked_add(encoded_hello_bytes)?.checked_add(DIGEST_BYTES)
    }

    /// Counts two encoding buffers, two outcome slots and the entry latch.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> Option<usize> {
        Some(5)
    }

    /// Reports one additional reached constructor/move carrier outside a resident field.
    #[must_use]
    pub const fn construction_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    pub(super) fn capture_once(&mut self, checkpoint: &HistoricalSessionCheckpointV1, maximum: Option<usize>)
        -> Result<(), HistoricalCheckpointErrorV1>
    {
        if self.entered {
            self.closed.get_or_insert(HistoricalCheckpointErrorV1::Invalid);
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        self.entered = true;
        self.completion = Some((|| {
            if let Some(maximum) = maximum {
                require_encoding_bound(checkpoint, maximum)?;
            }
            self.encode_inner(checkpoint)
        })());
        self.completion.as_ref().ok_or(HistoricalCheckpointErrorV1::Invalid)?.as_ref()
            .map(|_| ()).map_err(|e| *e)
    }

    fn encode_inner(&mut self, checkpoint: &HistoricalSessionCheckpointV1)
        -> Result<(), HistoricalCheckpointErrorV1>
    {
        self.context = Some(checkpoint.context.checkpoint_bytes());
        let context = self.context.as_deref().ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        let context_len =
            u32::try_from(context.len()).map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        let client_len = u32::try_from(checkpoint.client_hello.len())
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        let broker_len = u32::try_from(checkpoint.broker_hello.len())
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        if checkpoint.client_hello.is_empty()
            || checkpoint.broker_hello.is_empty()
            || checkpoint.client_hello.len() > CLIENT_HELLO_MAXIMUM_BYTES
            || checkpoint.broker_hello.len() > SERVER_HELLO_MAXIMUM_BYTES
            || checkpoint.peer.pid.is_none_or(|pid| pid == 0)
        {
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        self.encoded = Some(Vec::with_capacity(
            HEADER_BYTES
                + context.len()
                + checkpoint.client_hello.len()
                + checkpoint.broker_hello.len()
                + DIGEST_BYTES,
        ));
        let bytes = self.encoded.as_mut().ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&context_len.to_be_bytes());
        bytes.extend_from_slice(&client_len.to_be_bytes());
        bytes.extend_from_slice(&broker_len.to_be_bytes());
        bytes.extend_from_slice(&checkpoint.peer.uid.to_be_bytes());
        bytes.extend_from_slice(&checkpoint.peer.gid.to_be_bytes());
        bytes.extend_from_slice(&checkpoint.peer.pid.unwrap_or_default().to_be_bytes());
        bytes.extend_from_slice(&context);
        bytes.extend_from_slice(&checkpoint.client_hello);
        bytes.extend_from_slice(&checkpoint.broker_hello);
        let digest: [u8; 32] = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&*bytes)
            .finalize()
            .into();
        bytes.extend_from_slice(&digest);
        // The context temporary has no borrower after complete byte assembly.
        drop(self.context.take());
        Ok(())
    }

    pub(super) fn into_ordinary_result(mut self) -> Result<Vec<u8>, HistoricalCheckpointErrorV1> {
        if self.failure().is_some() {
            drop(self.context.take());
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        self.take_encoded_once()
    }
}

/// Retains the partial context, checkpoint, verification and canonical refusal.
#[doc(hidden)]
pub struct HistoricalSessionCheckpointDecodeCaptureV1 {
    context: BrokerSessionContextCheckpointDecodeCaptureV1,
    checkpoint: Option<HistoricalSessionCheckpointV1>,
    verify: HistoricalSessionCheckpointVerifyCaptureV1,
    encode: HistoricalSessionCheckpointEncodeCaptureV1,
    canonical: Option<Result<(), HistoricalCheckpointErrorV1>>,
    completion: Option<Result<(), HistoricalCheckpointErrorV1>>,
    closed: Option<HistoricalCheckpointErrorV1>,
    retained: bool,
    entered: bool,
}

impl Default for HistoricalSessionCheckpointDecodeCaptureV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl HistoricalSessionCheckpointDecodeCaptureV1 {
    /// Prearms fixed nested parsing destinations without allocating.
    #[must_use]
    pub fn new() -> Self {
        Self {
            context: BrokerSessionContextCheckpointDecodeCaptureV1::new(),
            checkpoint: None,
            verify: HistoricalSessionCheckpointVerifyCaptureV1::new(),
            encode: HistoricalSessionCheckpointEncodeCaptureV1::new(),
            canonical: None,
            completion: None,
            closed: None,
            retained: true,
            entered: false,
        }
    }

    /// Reports one additional reached constructor/move carrier outside a resident field.
    #[must_use]
    pub const fn construction_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    pub(super) fn ordinary() -> Self {
        Self { retained: false, ..Self::new() }
    }

    /// Borrows the first actual nested cause, including canonical mismatch.
    #[must_use]
    pub fn failure(&self) -> Option<&Cause> {
        self.context.failure().map(|e| e as &Cause)
            .or_else(|| self.verify.failure())
            .or_else(|| self.encode.failure())
            .or_else(|| self.canonical.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &Cause))
            .or_else(|| self.completion.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as &Cause))
            .or_else(|| self.closed.as_ref().map(|e| e as &Cause))
    }

    /// Borrows the reached checkpoint DATA, including on later verification Err.
    #[must_use]
    pub fn checkpoint(&self) -> Option<&HistoricalSessionCheckpointV1> {
        self.checkpoint.as_ref()
    }

    /// Moves a complete checkpoint once without cloning its hello buffers.
    ///
    /// # Errors
    /// Rejects incomplete, failed, repeated or already-consumed parsing.
    pub fn take_checkpoint_once(&mut self) -> Result<HistoricalSessionCheckpointV1, HistoricalCheckpointErrorV1> {
        if self.failure().is_none() && matches!(self.completion, Some(Ok(()))) {
            if let Some(value) = self.checkpoint.take() {
                return Ok(value);
            }
        }
        self.closed.get_or_insert(HistoricalCheckpointErrorV1::Invalid);
        Err(HistoricalCheckpointErrorV1::Invalid)
    }

    /// Reports the actual fixed destination including all embedded captures.
    #[must_use]
    pub const fn inline_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Bounds checkpoint/context ownership beyond decoded Hello projections.
    ///
    /// A successful verification disposes its pure inputs and unused transcript
    /// before encode begins. The reached checkpoint's two wire Vecs remain.
    #[must_use]
    pub fn receiving_nonprojection_heap_bytes_v1(encoded_hello_bytes: usize) -> Option<usize> {
        let verify = HistoricalSessionCheckpointVerifyCaptureV1::receiving_nonprojection_heap_bytes_v1(encoded_hello_bytes)?;
        let encode = HistoricalSessionCheckpointEncodeCaptureV1::receiving_heap_bytes_v1(encoded_hello_bytes)?;
        encoded_hello_bytes.checked_add(verify.max(encode))?
            .checked_add(BrokerSessionContextCheckpointDecodeCaptureV1::receiving_heap_bytes_v1())
    }

    /// Counts all nine parent fields plus each nested capture's controls.
    ///
    /// Embedded-destination fields are conservatively counted as parent cells
    /// as well as their child's own controls; no parent latch is omitted.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        BrokerSessionContextCheckpointDecodeCaptureV1::receiving_metadata_cells_v1()?
            .checked_add(HistoricalSessionCheckpointVerifyCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(HistoricalSessionCheckpointEncodeCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(9)
    }

    /// Bounds reached negotiation rows and namespace allocations.
    #[must_use]
    pub fn receiving_table_metadata_cells_v1(encoded_hello_bytes: usize) -> Option<usize> {
        HistoricalSessionCheckpointVerifyCaptureV1::receiving_table_metadata_cells_v1(encoded_hello_bytes)
    }

    pub(super) fn capture_once(&mut self, bytes: &[u8]) -> Result<(), HistoricalCheckpointErrorV1> {
        if self.entered {
            self.closed.get_or_insert(HistoricalCheckpointErrorV1::Invalid);
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        self.entered = true;
        self.completion = Some(self.decode_inner(bytes));
        self.completion.as_ref().ok_or(HistoricalCheckpointErrorV1::Invalid)?.as_ref()
            .map(|_| ()).map_err(|e| *e)
    }

    fn decode_inner(&mut self, bytes: &[u8]) -> Result<(), HistoricalCheckpointErrorV1> {
        if bytes.len() < HEADER_BYTES + DIGEST_BYTES
            || bytes.len() > MAXIMUM_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || read_u16(bytes, 8)? != 1
        {
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        let context_len = usize::try_from(read_u32(bytes, 10)?)
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        let client_len = usize::try_from(read_u32(bytes, 14)?)
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        let broker_len = usize::try_from(read_u32(bytes, 18)?)
            .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
        let peer = PeerCredentials {
            uid: read_u32(bytes, 22)?,
            gid: read_u32(bytes, 26)?,
            pid: Some(read_u32(bytes, 30)?),
        };
        let context_end = HEADER_BYTES
            .checked_add(context_len)
            .ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        let client_end = context_end
            .checked_add(client_len)
            .ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        let broker_end = client_end
            .checked_add(broker_len)
            .ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        if broker_end.checked_add(DIGEST_BYTES) != Some(bytes.len()) {
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        let context_bytes = bytes.get(HEADER_BYTES..context_end)
            .ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        let context = if self.retained {
            ProtectedBrokerSessionVerificationContextV1::from_checkpoint_bytes_retaining_v1(
                context_bytes, &mut self.context,
            ).map_err(|_| HistoricalCheckpointErrorV1::Invalid)?;
            self.context.take_context_once().map_err(|_| HistoricalCheckpointErrorV1::Invalid)?
        } else {
            ProtectedBrokerSessionVerificationContextV1::from_checkpoint_bytes(context_bytes)
                .map_err(|_| HistoricalCheckpointErrorV1::Invalid)?
        };
        self.checkpoint = Some(HistoricalSessionCheckpointV1 {
            context,
            client_hello: bytes
                .get(context_end..client_end)
                .ok_or(HistoricalCheckpointErrorV1::Invalid)?
                .to_vec(),
            broker_hello: bytes
                .get(client_end..broker_end)
                .ok_or(HistoricalCheckpointErrorV1::Invalid)?
                .to_vec(),
            peer,
        });
        let checkpoint = self.checkpoint.as_ref().ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        if self.retained {
            checkpoint.verify_retaining(&mut self.verify)?;
            // The old decoder discarded this temporary verified transcript
            // before encoding. Its successful pure scratch has no next borrower.
            drop(self.verify.take_transcript_once()?);
            self.verify.dispose_successful_inputs();
            checkpoint.encode_retaining(&mut self.encode)?;
            self.canonical = Some(if self.encode.encoded() == Some(bytes) {
                Ok(())
            } else {
                Err(HistoricalCheckpointErrorV1::Invalid)
            });
            if !matches!(self.canonical, Some(Ok(()))) {
                return Err(HistoricalCheckpointErrorV1::Invalid);
            }
            drop(self.encode.take_encoded_once()?);
        } else {
            checkpoint.verify()?;
            if checkpoint.encode()? != bytes {
                return Err(HistoricalCheckpointErrorV1::Invalid);
            }
        }
        Ok(())
    }

    pub(super) fn into_ordinary_result(mut self) -> Result<HistoricalSessionCheckpointV1, HistoricalCheckpointErrorV1> {
        if self.failure().is_some() {
            // The old temporary canonical encoding was already disposed by its
            // immediate adapter, before the reached checkpoint local.
            drop(self.checkpoint.take());
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        self.take_checkpoint_once()
    }
}

#[cfg(test)]
mod tests;
