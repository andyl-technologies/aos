//! Joins completed Capture17 custody to its two uploads and final confirmation.
//!
//! This reader consumes actual retained Controller history. Its private result
//! carries historical correspondence DATA; it cannot reconstruct a live SDK
//! attempt, spend a native slot, issue a Source claim, or install a fresh node.
//! Native authentication and signed archive ancestry remain independent checks.

use super::*;
use crate::bodies::{decode_request, decode_response};
use crate::envelope::{MessageKind, Method, RequestOrigin};
use crate::reference_packet::service::restored_settled_capture::*;
use crate::reference_packet::service::restored_settled_confirmation::*;
use crucible_node_contract::canonical;

#[path = "capture/auxiliary.rs"]
mod auxiliary;

#[path = "capture/selected_construction.rs"]
mod selected_construction;
pub use selected_construction::{
    historical_restored_settled_capture17_selected_counter_scratch_data,
    historical_restored_settled_capture17_selected_retained_construction_bytes_data,
    historical_restored_settled_capture17_selected_validation_transient_bytes_data,
};

/// Retains checked actual Capture and confirmation pairs as inert history.
///
/// There is no public field, decoder, Clone implementation, or live conversion.
/// The parent Controller retains the full original bytes and partial DOM even
/// when this independent typed validation refuses an input.
pub struct ValidatedHistoricalRestoredSettledCapture17 {
    capture: HistoricalPair17,
    confirmation: HistoricalPair17,
    request: PacketRestoredSettledCaptureRequest,
    context: PacketRestoredSettledCaptureContext,
    artifact: PacketRestoredSettledCaptureArtifact,
    confirmation_request: PacketRestoredSettledAfterConfirmationRequest,
    receipt: PacketRestoredSettledAfterConfirmationReceipt,
    canonical_original: Vec<u8>,
    prefix_frontier: U64,
}

struct HistoricalPair17 {
    original: Envelope,
    terminal: Envelope,
    response: ResponseBody,
    frontier: U64,
}

impl ValidatedHistoricalRestoredSettledCapture17 {
    /// Checks the exact completed SDK owner against its actual Controller cut.
    ///
    /// The enclosing Source reader must admit this reader's independent typed,
    /// canonical, and auxiliary validation demand before calling. This method
    /// neither fetches content nor infers a frontier from a request or response.
    ///
    /// # Errors
    /// Refuses incomplete owners, changed raw/typed journal pairs, foreign
    /// routes, assigned contexts, upload payloads or ordering, missing content,
    /// unequal confirmation, and a final frontier different from this cut.
    pub fn validate_data(
        controller: &ValidatedControllerSettledHistory17,
    ) -> Result<Self, ProviderError> {
        let root = controller.parts_data()?.as_object().ok_or_else(invalid)?;
        let history_value = field(root, "capture")?;
        super::super::current_sdk_capture17::validate_capture_data(history_value)?;
        let history = history_value.as_object().ok_or_else(invalid)?;
        text(field(history, "stage")?, "complete")?;
        let request: PacketRestoredSettledCaptureRequest = read(field(history, "request")?)?;
        request.validate_data()?;
        let prefix_frontier: U64 = read(field(history, "prefix_frontier")?)?;
        if prefix_frontier != request.history_next_sequence {
            return Err(invalid());
        }
        let session = field(root, "session")?.as_object().ok_or_else(invalid)?;
        let authority = field(session, "authority")?
            .as_object()
            .ok_or_else(invalid)?;
        let limits: crate::handshake::Limits = read(field(authority, "limits")?)?;
        let maximum_frame = usize::try_from(limits.frame_bytes.get()).map_err(|_| invalid())?;
        let current: U64 = read(field(session, "sequence")?)?;
        let node: Id = read(field(root, "node")?)?;
        let owner: Id = read(field(root, "execution_owner")?)?;
        if request.scope.target.node != node || request.scope.target.owner != owner {
            return Err(invalid());
        }

        let capture = pair_data(history, "capture_frontier", root)?;
        let request_id: Id = read(field(history, "request_id")?)?;
        let operation: Id = read(field(history, "operation_id")?)?;
        if capture.original.request_id.0.as_ref() != Some(&request_id)
            || capture.original.operation_id.0.as_ref() != Some(&operation)
            || request.capture_operation != operation
            || capture.original.method != Method::Begin
        {
            return Err(invalid());
        }
        let body: BeginRequest = read(field(history, "body")?)?;
        let arguments: CaptureArguments = read(field(history, "arguments")?)?;
        if body.kind != BeginKind::Capture
            || !body.extensions.is_empty()
            || body.decoded_arguments()? != BeginArguments::Capture(arguments)
            || field(history, "body")? != &Value::Object(capture.original.body.clone())
        {
            return Err(invalid());
        }
        let context: PacketRestoredSettledCaptureContext = read(field(history, "context")?)?;
        let artifact: PacketRestoredSettledCaptureArtifact = read(field(history, "artifact")?)?;
        context.validate_data()?;
        artifact.validate_data()?;
        let assigned = restored_settled_capture_assigned_request_digest_data(
            &capture.original,
            maximum_frame,
        )?;
        if context.request != request
            || artifact.request != request
            || context.assigned_request.as_slice() != assigned
            || artifact.proof.context_digest.as_slice()
                != restored_settled_capture_context_digest_data(&context)?
            || capture
                .original
                .extensions
                .get(RESTORED_SETTLED_CAPTURE_FEATURE)
                != Some(&value_data(&artifact)?)
        {
            return Err(invalid());
        }
        if &value_data(&request)? != field(history, "unsigned_request")? {
            return Err(invalid());
        }
        let canonical_original: Vec<u8> = read(field(history, "canonical")?)?;
        if canonical_original != canonical::canonical_json(&value_data(&capture.original)?)? {
            return Err(invalid());
        }
        let after_uploads = auxiliary::authenticate_uploads_data(
            history,
            root,
            &request,
            &limits,
            prefix_frontier,
        )?;
        if capture.original.sequence != after_uploads {
            return Err(invalid());
        }
        authenticate_roots_data(history, &capture.terminal, controller)?;
        let Some(MethodResult::Capture(result)) = capture.response.result.as_ref() else {
            return Err(invalid());
        };
        if result.owner_state_refs.len() != 1 {
            return Err(invalid());
        }

        let confirmation_history = field(history, "confirmation")?
            .as_object()
            .ok_or_else(invalid)?;
        let confirmation = pair_data(confirmation_history, "frontier", root)?;
        let confirmation_request: PacketRestoredSettledAfterConfirmationRequest =
            read(field(confirmation_history, "request")?)?;
        let receipt: PacketRestoredSettledAfterConfirmationReceipt =
            read(field(confirmation_history, "receipt")?)?;
        confirmation_request.validate_data()?;
        receipt.validate_data()?;
        let confirmation_id: Id = read(field(confirmation_history, "request_id")?)?;
        let Some(MethodResult::Poll(poll)) = confirmation.response.result.as_ref() else {
            return Err(invalid());
        };
        let poll_body: PollRequest =
            serde_json::from_value(Value::Object(confirmation.original.body.clone()))
                .map_err(crucible_node_contract::ContractError::from)?;
        let terminal_bytes = canonical::canonical_json(&value_data(&capture.terminal)?)?;
        if confirmation.original.method != Method::Poll
            || confirmation.original.sequence != capture.frontier
            || confirmation.original.request_id.0.as_ref() != Some(&confirmation_id)
            || confirmation.original.operation_id.0.as_ref() != Some(&operation)
            || confirmation.original.capture_owner_id.0.as_ref() != Some(&request.capture_owner)
            || confirmation.original.extensions.len() != 1
            || confirmation
                .original
                .extensions
                .get(PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE)
                != Some(field(confirmation_history, "extension")?)
            || field(confirmation_history, "extension")? != &value_data(&confirmation_request)?
            || confirmation.terminal.extensions.len() != 1
            || confirmation
                .terminal
                .extensions
                .get(PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE)
                != Some(&value_data(&receipt)?)
            || !poll_body.extensions.is_empty()
            || poll_body.after_observation_sequence != U64::new(0)
            || receipt.capture != confirmation_request
            || confirmation_request.capture_request_id != request_id
            || confirmation_request.capture_operation_id != operation
            || confirmation_request.capture_request_hash
                != capture.original.request_hash(RequestOrigin::Controller)?
            || confirmation_request.capture_terminal_sequence != capture.terminal.sequence
            || confirmation_request.capture_terminal_hash
                != canonical::hash(
                    PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN,
                    &terminal_bytes,
                )?
            || confirmation_request.settled_capture_request
                != canonical::content_ref(&canonical_original, "application/json")?
            || confirmation_request.native_snapshot_ref != result.capture_manifest
            || confirmation_request.native_control_ref != result.owner_state_refs[0]
            || confirmation_request.native_anchor_ref != result.unchanged_cut_receipt
            || poll.operation_id != operation
            || !poll.observations.is_empty()
            || poll.next_observation_sequence != U64::new(0)
            || poll.outcome.0.as_ref() != Some(&capture.terminal.body)
            || field(confirmation_history, "roots")?
                .as_array()
                .ok_or_else(invalid)?
                .len()
                != 0
            || confirmation.frontier != current
        {
            return Err(invalid());
        }
        controller.authenticate_completed_content_reference_data(&receipt.native_after_ref)?;
        Ok(Self {
            capture,
            confirmation,
            request,
            context,
            artifact,
            confirmation_request,
            receipt,
            canonical_original,
            prefix_frontier,
        })
    }

    /// Borrows the real Capture pair and independently decoded terminal.
    pub fn capture_pair_data(&self) -> (&Envelope, &Envelope, &ResponseBody) {
        (
            &self.capture.original,
            &self.capture.terminal,
            &self.capture.response,
        )
    }

    /// Borrows the actual final Poll pair and independently decoded terminal.
    pub fn confirmation_pair_data(&self) -> (&Envelope, &Envelope, &ResponseBody) {
        (
            &self.confirmation.original,
            &self.confirmation.terminal,
            &self.confirmation.response,
        )
    }

    /// Borrows the exact signed request retained by the actual SDK owner.
    pub fn request_data(&self) -> &PacketRestoredSettledCaptureRequest {
        &self.request
    }

    /// Borrows the assigned context without authenticating its native MAC.
    pub fn context_data(&self) -> &PacketRestoredSettledCaptureContext {
        &self.context
    }

    /// Borrows the actual artifact for the separate private native verifier.
    pub fn artifact_data(&self) -> &PacketRestoredSettledCaptureArtifact {
        &self.artifact
    }

    /// Borrows the final confirmation request joined to both actual pairs.
    pub fn confirmation_request_data(&self) -> &PacketRestoredSettledAfterConfirmationRequest {
        &self.confirmation_request
    }

    /// Borrows the fourth-object receipt joined to the actual Poll terminal.
    pub fn receipt_data(&self) -> &PacketRestoredSettledAfterConfirmationReceipt {
        &self.receipt
    }

    /// Returns the actual saved cut before either auxiliary transfer.
    pub const fn prefix_frontier_data(&self) -> U64 {
        self.prefix_frontier
    }

    /// Returns the actual saved cut after the fourth body and confirmation.
    pub const fn frontier_data(&self) -> U64 {
        self.confirmation.frontier
    }

    /// Borrows the exact retained proof-filled original bytes.
    pub fn canonical_original_data(&self) -> &[u8] {
        &self.canonical_original
    }

    /// Counts all actual independent typed result backing without encoding it.
    ///
    /// # Errors
    /// Refuses metadata traversal or checked layout overflow.
    pub fn retained_metadata_data(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        for pair in [&self.capture, &self.confirmation] {
            observer.observe(&pair.original)?;
            observer.observe(&pair.terminal)?;
            crate::retained_metadata::historical_response_body_data(&pair.response)?
                .observe_retained_metadata_data(&mut observer)?;
        }
        observer.observe(&self.request)?;
        observer.observe(&self.context)?;
        observer.observe(&self.artifact)?;
        observer.observe(&self.confirmation_request)?;
        observer.observe(&self.receipt)?;
        observer.observe(&self.canonical_original)?;
        Ok(observer.finish())
    }
}

fn value_data(value: &impl serde::Serialize) -> Result<Value, ProviderError> {
    serde_json::to_value(value)
        .map_err(crucible_node_contract::ContractError::from)
        .map_err(Into::into)
}

fn pair_data(
    history: &Map<String, Value>,
    frontier: &str,
    root: &Map<String, Value>,
) -> Result<HistoricalPair17, ProviderError> {
    text(field(history, "stage")?, "complete")?;
    if field(history, "cut_present")?.as_bool() != Some(true) {
        return Err(invalid());
    }
    let original: Envelope = read(field(history, "original")?)?;
    let terminal: Envelope = read(field(history, "terminal")?)?;
    original.validate()?;
    terminal.validate()?;
    original.matches_response(&terminal)?;
    let saved: U64 = read(field(history, frontier)?)?;
    let id: Id = read(field(history, "request_id")?)?;
    let session = field(root, "session")?.as_object().ok_or_else(invalid)?;
    let authority = field(session, "authority")?
        .as_object()
        .ok_or_else(invalid)?;
    let node: Id = read(field(root, "node")?)?;
    let session_id: Id = read(field(authority, "session")?)?;
    let incarnation: Id = read(field(authority, "incarnation")?)?;
    let current: U64 = read(field(session, "sequence")?)?;
    if original.message != MessageKind::Request
        || original.request_id.0.as_ref() != Some(&id)
        || original.node_id.0.as_ref() != Some(&node)
        || original.session_id.0.as_ref() != Some(&session_id)
        || original.incarnation_id.0.as_ref() != Some(&incarnation)
        || original.execution_owner_id.0.is_some()
        || original.capture_owner_id.0.is_none()
        || saved <= original.sequence
        || saved > current
    {
        return Err(invalid());
    }
    let custody = tuple(field(root, "custody")?, 6)?;
    let journal = custody[3].as_object().ok_or_else(invalid)?;
    let actual = object(
        journal.get(id.as_str()).ok_or_else(invalid)?,
        &["request", "identity", "response"],
    )?;
    if field(actual, "request")? != field(history, "original")?
        || field(actual, "response")? != field(history, "terminal")?
        || read::<HashRef>(field(actual, "identity")?)?
            != original.request_hash(RequestOrigin::Controller)?
    {
        return Err(invalid());
    }
    let response = decode_response(
        &decode_request(original.method, &original.body)?,
        &terminal.body,
    )?;
    if !matches!(
        &response.shape,
        crate::bodies::ResponseShape::Completed {
            operation_state: crate::bodies::OperationState::Completed,
            ..
        }
    ) || value_data(&crate::retained_metadata::historical_response_body_data(
        &response,
    )?)? != *field(history, "decoded")?
    {
        return Err(invalid());
    }
    Ok(HistoricalPair17 {
        original,
        terminal,
        response,
        frontier: saved,
    })
}

fn authenticate_roots_data(
    history: &Map<String, Value>,
    terminal: &Envelope,
    controller: &ValidatedControllerSettledHistory17,
) -> Result<(), ProviderError> {
    let roots: Vec<ContentRef> = read(field(history, "roots")?)?;
    let mut actual = Vec::new();
    crate::client::original_suffix_response_references_data(terminal, &mut actual)?;
    if actual != roots {
        return Err(invalid());
    }
    for reference in &roots {
        controller.authenticate_completed_content_reference_data(reference)?;
    }
    Ok(())
}

/// Quotes the independent retained owner returned by the completed Capture reader.
///
/// The caller supplies the byte extent of its actual opaque Controller owner
/// before constructing this additional SDK history. This is storage DATA only;
/// validation, transient construction and any earlier SDK copy remain separate.
///
/// The four Envelopes, two independent ResponseBodies, request, context,
/// artifact, confirmation request and receipt correspond to disjoint retained
/// Controller subtrees. `pair_data` compares both decoded responses, including
/// their raw shapes and typed results, with their own `decoded` subtrees. Their
/// combined String, Value and map backing therefore fits one whole-input lexical
/// DOM bound; nested copies of the request already have distinct input fields.
///
/// Typed vectors additionally store Ids in Capture arguments and ContentRefs in
/// the Capture result. A successful final Poll has no observations. Each vector
/// element and each vector container consumes a lexical event; four requests per
/// element plus eight minimum slots per container bound geometric reservation.
/// The canonical-original byte vector has its own independently retained bank.
///
/// # Errors
/// Refuses a zero extent, unsupported selected JSON layouts or checked storage
/// overflow. The result grants no decode, Source or native allocation authority.
pub fn historical_restored_settled_capture17_retained_construction_bytes_data(
    controller_encoded_bytes: usize,
) -> Result<usize, ProviderError> {
    let extent =
        crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(
            controller_encoded_bytes,
        )?;
    let typed_element = size_of::<Id>().max(size_of::<ContentRef>());
    let typed_vectors = extent
        .maximum_value_nodes
        .checked_mul(12)
        .and_then(|slots| slots.checked_mul(typed_element))
        .ok_or_else(invalid)?;
    let canonical_original = controller_encoded_bytes
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(8))
        .ok_or_else(invalid)?;

    // This header contains both HistoricalPair17 triples, every inline DTO,
    // the canonical Vec handle and prefix frontier, with their real padding.
    size_of::<ValidatedHistoricalRestoredSettledCapture17>()
        .checked_add(extent.value_dom_requested_bytes)
        .and_then(|bytes| bytes.checked_add(typed_vectors))
        .and_then(|bytes| bytes.checked_add(canonical_original))
        .ok_or_else(invalid)
}

/// Quotes independent typed history validation and canonical temporaries.
///
/// The whole Source constructor separately admits the parent's raw/DOM owner and
/// this result's retained actual backing. This closed bound covers simultaneous
/// Capture/confirmation copies plus one auxiliary original and its context. It
/// cannot increase a Controller/native ceiling or authorize any construction.
///
/// # Errors
/// Refuses zero extent or checked storage-layout overflow.
pub fn historical_restored_settled_capture17_validation_transient_bytes_data(
    maximum_encoded: usize,
) -> Result<usize, ProviderError> {
    let extent =
        crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(
            maximum_encoded,
        )?;
    let typed = extent
        .maximum_value_nodes
        .checked_mul(typed_layouts_data())
        .ok_or_else(invalid)?;
    extent
        .canonical_pass_requested_bytes()?
        .checked_mul(12)
        .and_then(|n| n.checked_add(typed))
        .and_then(|n| n.checked_add(historical_restored_settled_capture17_counter_scratch_data()))
        .ok_or_else(invalid)
}

fn typed_layouts_data() -> usize {
    use crate::reference_packet::service::restored_settled_capture::upload::*;
    size_of::<ValidatedHistoricalRestoredSettledCapture17>()
        + size_of::<HistoricalPair17>() * 3
        + size_of::<Envelope>()
        + size_of::<ResponseBody>()
        + size_of::<MethodResult>()
        + size_of::<PacketRestoredSettledCaptureRequest>()
        + size_of::<PacketRestoredSettledCaptureContext>()
        + size_of::<PacketRestoredSettledCaptureArtifact>()
        + size_of::<PacketRestoredSettledCaptureUploadRequest>()
        + size_of::<PacketRestoredSettledCaptureUploadContext>()
        + size_of::<PacketRestoredSettledCaptureUploadArtifact>()
        + size_of::<PacketRestoredSettledCaptureUploadContinuation>()
        + size_of::<PacketRestoredSettledAfterConfirmationRequest>()
        + size_of::<PacketRestoredSettledAfterConfirmationReceipt>()
        + size_of::<BeginRequest>()
        + size_of::<BeginArguments>()
        + size_of::<CaptureArguments>()
        + size_of::<PollRequest>()
        + size_of::<BlobBeginRequest>()
        + size_of::<BlobChunkRequest>()
        + size_of::<BlobFinishRequest>()
        + size_of::<ContentRef>()
        + size_of::<Id>()
        + size_of::<String>()
        + size_of::<Value>()
        + size_of::<crucible_node_contract::Bytes>()
}

/// Names fixed views used by the actual completed Capture17 history reader.
pub fn historical_restored_settled_capture17_counter_scratch_data() -> usize {
    typed_layouts_data()
        + size_of::<blake3::Hasher>() + size_of::<blake3::Hash>()
        + size_of::<Result<ValidatedHistoricalRestoredSettledCapture17, ProviderError>>()
        + size_of::<Result<HistoricalPair17, ProviderError>>()
        + size_of::<Result<(), ProviderError>>() + size_of::<Result<U64, ProviderError>>()
        + size_of::<&ValidatedControllerSettledHistory17>()
        + size_of::<&Map<String, Value>>() * 8 + size_of::<Vec<ContentRef>>() * 2
        + size_of::<Vec<u8>>() * 2 + size_of::<Value>() * 4
        + size_of::<crate::handshake::Limits>()
        + size_of::<crate::reference_packet::service::native_startup::PacketRestoredSettledCaptureUploadGeometryData>()
        + crate::client::original_suffix_response_references_counter_scratch_data()
        + restored_settled_capture_contract_counter_scratch_data()
        + crate::reference_packet::service::restored_settled_capture::upload::restored_settled_capture_upload_counter_scratch_data()
        + restored_settled_after_confirmation_counter_scratch_data()
}

impl ValidatedControllerSettledHistory17 {
    /// Compares a native-owned historical pair with this exact Controller journal.
    ///
    /// This membership check preserves original byte/typed equality and request
    /// identity. It performs no transport operation and makes no currency claim.
    ///
    /// # Errors
    /// Refuses an invalid or absent original, another raw terminal, a different
    /// controller-origin hash, or a changed request/response correlation.
    pub fn authenticate_historical_controller_pair17_data(
        &self,
        original: &Envelope,
        terminal: &Envelope,
    ) -> Result<(), ProviderError> {
        original.validate()?;
        terminal.validate()?;
        original.matches_response(terminal)?;
        let id = original.request_id.0.as_ref().ok_or_else(invalid)?;
        let root = self.parts_data()?.as_object().ok_or_else(invalid)?;
        let custody = tuple(field(root, "custody")?, 6)?;
        let journal = custody[3].as_object().ok_or_else(invalid)?;
        let actual = object(
            journal.get(id.as_str()).ok_or_else(invalid)?,
            &["request", "identity", "response"],
        )?;
        if field(actual, "request")? != &value_data(original)?
            || field(actual, "response")? != &value_data(terminal)?
            || read::<HashRef>(field(actual, "identity")?)?
                != original.request_hash(RequestOrigin::Controller)?
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "capture/retained_construction_tests.rs"]
mod retained_construction_tests;
