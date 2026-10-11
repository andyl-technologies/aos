//! Finite source-planned loss after an original Begin write and before any reply read.
//!
//! The retained frame is the canonical envelope actually passed to the sender.
//! A completed write does not establish native execution. The source callback
//! retains its own original process custody; this child only fences transport.
//!
//! A projection of the inert record retains completion absence explicitly:
//!
//! ```json
//! {"schema":"crucible.reference.original-response-loss.v1","write_completed":true,"response_read":false}
//! ```

use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crucible_node_contract::{Bytes, HashRef, Id, U64, canonical};
use serde::Serialize;

use crate::ProviderError;
use crate::bodies::{BeginArguments, RequestBody, decode_request};
use crate::envelope::{Envelope, Method, RequestOrigin};

use super::ReferenceController;

const MAXIMUM_ORIGINAL_BYTES: usize = 1024 * 1024;

/// Authenticates one source-predeclared original without granting native authority.
pub trait OriginalResponseLossQualification {
    /// Checks exact source scope, original input and current native custody before send.
    ///
    /// # Errors
    /// Refuses any changed or unavailable original source premise.
    fn authenticate_before_send(&self, original: &Envelope) -> Result<(), ProviderError>;

    /// Executes the predeclared loss action after a successful original write.
    ///
    /// Transport is already fenced. A failure or unwind cannot permit a cached
    /// request with no response to be sent again on the original connection.
    ///
    /// # Errors
    /// Refuses unavailable original signal custody or incomplete containment.
    fn after_original_write(&self, original: &Envelope) -> Result<(), ProviderError>;
}

/// Exposes immutable observations without a socket, controller or signal handle.
#[derive(Clone)]
pub struct OriginalResponseLossObservationHandle {
    archive: Arc<Mutex<OriginalResponseLossObservation>>,
}

/// Retains one original transmission whose completion was deliberately unread.
#[derive(Clone, Serialize)]
pub struct OriginalResponseLossObservation {
    /// Names the separate original-loss observation edition.
    pub schema: &'static str,
    /// Names canonical bytes supplied to the actual sender.
    pub encoding: &'static str,
    /// Retains the original connection session.
    pub session_id: Id,
    /// Retains the original provider incarnation.
    pub incarnation_id: Id,
    /// Retains the predeclared original request identity.
    pub request_id: Id,
    /// Retains the actual first-original semantic hash, when dispatch was attempted.
    pub request_hash: Option<HashRef>,
    /// Retains the outgoing lane sequence independently of any provider lane.
    pub sent_sequence: Option<U64>,
    /// Retains the exact canonical original envelope before its first write.
    pub request: Vec<u8>,
    /// Records that the actual sender completed the original frame write.
    pub write_completed: bool,
    /// Records that the connection was fenced before reading a completion.
    pub fenced_before_read: bool,
    /// Records that the source loss callback returned successfully.
    pub loss_action_completed: bool,
    /// Keeps completion absence explicit; this hook never reads a response.
    pub response_read: bool,
}

pub(crate) struct OriginalResponseLossRecorder {
    request_id: Id,
    qualifier: Rc<dyn OriginalResponseLossQualification>,
    private_token: Bytes,
    archive: Arc<Mutex<OriginalResponseLossObservation>>,
    maximum_bytes: usize,
    selected: bool,
}

impl OriginalResponseLossObservationHandle {
    /// Copies the original record under an independently bounded observation cap.
    ///
    /// # Errors
    /// Refuses unavailable storage or a cap below the already retained frame.
    pub fn snapshot(
        &self,
        maximum_bytes: usize,
    ) -> Result<OriginalResponseLossObservation, ProviderError> {
        let archive = self.archive.lock().map_err(|_| unavailable())?;
        if maximum_bytes == 0
            || maximum_bytes > MAXIMUM_ORIGINAL_BYTES
            || archive.request.len() > maximum_bytes
        {
            return Err(exhausted());
        }
        Ok(archive.clone())
    }
}

impl ReferenceController {
    /// Reserves one explicit source-planned original response-loss observation.
    ///
    /// Installation must precede all controls. The default session has no loss
    /// hook. Only a structurally valid original quantum Begin can be selected;
    /// no cached response or retained-original resend can trigger this action.
    /// This mechanism grants no qualification or ordinary execution permission.
    ///
    /// # Errors
    /// Refuses late or repeated installation, invalid finite byte credit, failed
    /// reservation or unavailable original connection scope.
    pub fn install_original_response_loss(
        &mut self,
        request_id: Id,
        qualifier: Rc<dyn OriginalResponseLossQualification>,
        maximum_bytes: usize,
    ) -> Result<OriginalResponseLossObservationHandle, ProviderError> {
        if self.custody.originals().next().is_some()
            || self.session.original_response_loss.is_some()
        {
            return Err(unavailable());
        }
        if maximum_bytes == 0 || maximum_bytes > MAXIMUM_ORIGINAL_BYTES {
            return Err(exhausted());
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(maximum_bytes)
            .map_err(|_| exhausted())?;
        let archive = Arc::new(Mutex::new(OriginalResponseLossObservation {
            schema: "crucible.reference.original-response-loss.v1",
            encoding: "canonical-first-original-transmitted-envelope-v1",
            session_id: self.session.authority().session_id().clone(),
            incarnation_id: self.session.authority().incarnation_id().clone(),
            request_id: request_id.clone(),
            request_hash: None,
            sent_sequence: None,
            request: bytes,
            write_completed: false,
            fenced_before_read: false,
            loss_action_completed: false,
            response_read: false,
        }));
        self.session.original_response_loss = Some(OriginalResponseLossRecorder {
            request_id,
            qualifier,
            private_token: self.bootstrap.admission_token.clone(),
            archive: archive.clone(),
            maximum_bytes,
            selected: false,
        });
        Ok(OriginalResponseLossObservationHandle { archive })
    }
}

impl OriginalResponseLossRecorder {
    pub(crate) fn prepare(&mut self, request: &Envelope) -> Result<bool, ProviderError> {
        if request.request_id.0.as_ref() != Some(&self.request_id) {
            return Ok(false);
        }
        if self.selected {
            return Err(unavailable());
        }
        let RequestBody::Begin(body) = decode_request(request.method, &request.body)? else {
            return Err(unavailable());
        };
        if request.method != Method::Begin
            || !matches!(body.decoded_arguments()?, BeginArguments::QuantumBegin(_))
        {
            return Err(unavailable());
        }
        super::evidence::reject_private_envelope(request, self.private_token.as_slice())?;
        self.qualifier.authenticate_before_send(request)?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(request).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        if bytes.len() > self.maximum_bytes {
            return Err(exhausted());
        }
        let mut archive = self.archive.lock().map_err(|_| unavailable())?;
        archive.request.extend_from_slice(&bytes);
        archive.request_hash = Some(request.request_hash(RequestOrigin::Controller)?);
        archive.sent_sequence = Some(request.sequence);
        self.selected = true;
        Ok(true)
    }

    pub(crate) fn written_and_fenced(&self) -> Result<(), ProviderError> {
        let mut archive = self.archive.lock().map_err(|_| unavailable())?;
        archive.write_completed = true;
        archive.fenced_before_read = true;
        Ok(())
    }

    pub(crate) fn after_original_write(&self, request: &Envelope) -> Result<(), ProviderError> {
        self.qualifier.after_original_write(request)?;
        self.archive
            .lock()
            .map_err(|_| unavailable())?
            .loss_action_completed = true;
        Ok(())
    }
}

fn unavailable() -> ProviderError {
    ProviderError::Correlation("original response-loss scope unavailable")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("original response-loss frame credit")
}
