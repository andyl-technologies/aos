//! Checks the original Capture and fourth-object Poll against actual literal I/O.
//!
//! The original controller remains borrowed throughout. Every retained frame
//! must correspond to its exact typed original, including assigned sequence and
//! complete header/body progress. This predicate verifies the transport portion
//! of the local settlement journal; native/semantic state and fresh enrollment
//! remain separate required checks before the journal can authorize anything.

use super::*;
use crate::node_adapters::cnp::CnpSemanticCaptureScope;
use crucible_node_transport::{
    bodies::{
        BeginArguments, MethodResult, RequestBody, ResponseShape, decode_request, decode_response,
    },
    client::{ClientOriginal, CnpController},
    connection::OriginalNative5FrameHistory,
    envelope::{MessageKind, Method, RequestOrigin},
    protocol_snapshot::owned11::outer::HistoricalControllerState,
    reference_packet::service::confirmation::{
        PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION, PacketNative5ConfirmationSelection,
        PacketNativeAfterConfirmationReceipt,
    },
    transport::original_frames::{FrameDirection, OriginalFrame},
};

impl PacketCompleteSemanticSource {
    /// Authenticates actual Capture/fourth-Poll originals and every proof ACK.
    ///
    /// No source journal, installed capture or fresh token is issued here. The
    /// native before/after whole-state transition, common semantic history,
    /// ancestry and full allocation admission must also pass before sealing.
    ///
    /// # Errors
    /// Refuses changed ticket/source/controller, incomplete or repeated literal
    /// I/O, another Capture/Poll, missing or altered object bytes, any unrelated
    /// suffix request, incomplete transfer or invalid acknowledgement.
    pub fn authenticate_original_capture_settlement_transcript(
        &self,
        scope: &CnpSemanticCaptureScope<'_>,
        ticket: &OriginalLineageOwnerCaptureTicket<'_>,
        runtime: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        confirmation_request: &Id,
        receipt: &PacketNativeAfterConfirmationReceipt,
    ) -> Result<(), OperationFailure> {
        let realized = scope.realization()?;
        self.authenticate_witness_scope(&realized)?;
        if self.selected_confirmation_selection()?
            != Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5)
            || realized
                .controller
                .original_native5_confirmation_selection()
                .map_err(unknown)?
                != Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5)
        {
            return Err(refused(
                "Capture transcript selected confirmation is absent",
            ));
        }
        let active = scope
            .native
            .runtime
            .as_ref()
            .and_then(|state| state.active.as_ref())
            .ok_or_else(|| refused("Capture transcript active authority absent"))?;
        ticket
            .authenticate_scope(
                active,
                runtime,
                runtime_object,
                scope.owner,
                &self.installation().owner.owner.participant_ids,
            )
            .map_err(unknown)?;
        if receipt.capture.capture_operation_id != *ticket.operation_id() {
            return Err(refused("Capture transcript operation differs from ticket"));
        }
        let capture = realized
            .controller
            .original(&receipt.capture.capture_request_id)
            .ok_or_else(|| refused("Capture transcript original absent"))?;
        let request =
            decode_request(capture.request.method, &capture.request.body).map_err(unknown)?;
        let RequestBody::Begin(begin) = request else {
            return Err(refused("Capture transcript request is not Begin"));
        };
        let BeginArguments::Capture(arguments) = begin.decoded_arguments().map_err(unknown)? else {
            return Err(refused("Capture transcript Begin is not Capture"));
        };
        if arguments.capture_id != *ticket.capture_id()
            || arguments.participant_ids != ticket.participants()
            || arguments.cut != ticket.cut()
            || arguments.event_ordinal != ticket.ordinal()
            || capture.request.capture_owner_id.0.as_ref() != Some(&ticket.owner().owner)
        {
            return Err(refused(
                "Capture transcript arguments differ from original ticket",
            ));
        }
        verify_controller(realized.controller, confirmation_request, receipt)?;
        self.authenticate_witness_scope(&realized)
    }
}

fn verify_controller(
    controller: &CnpController,
    confirmation_request: &Id,
    receipt: &PacketNativeAfterConfirmationReceipt,
) -> Result<(), OperationFailure> {
    let history = controller
        .original_native5_frame_history()
        .map_err(unknown)?;
    verify_transcript(
        &LiveTranscript {
            controller,
            history,
        },
        confirmation_request,
        receipt,
    )
}

impl PacketCompleteSemanticSource {
    /// Authenticates complete archived typed/raw Capture and confirmation history.
    ///
    /// This data predicate grants no live authority. The installed archive factory
    /// separately verifies source/backend identity, common semantics, ancestry and
    /// the exact native model/Control transition before it may accept an owner.
    ///
    /// # Errors
    /// Refuses partial historical classes, changed typed/raw originals, incomplete
    /// proof transfers, unrelated suffix frames or unexhausted history.
    pub fn authenticate_archived_capture_settlement_transcript_data(
        historical: &HistoricalControllerState,
        confirmation_request: &Id,
        receipt: &PacketNativeAfterConfirmationReceipt,
    ) -> Result<(), OperationFailure> {
        historical
            .require_complete_reader_state()
            .map_err(unknown)?;
        verify_transcript(historical, confirmation_request, receipt)
    }
}

trait TranscriptState {
    fn original(&self, id: &Id) -> Option<&ClientOriginal>;
    fn originals_by_origin(&self, origin: RequestOrigin) -> impl Iterator<Item = &ClientOriginal>;
    fn content(&self, reference: &ContentRef) -> Result<&[u8], OperationFailure>;
    fn frames(&self) -> Result<impl Iterator<Item = OriginalFrame<'_>>, OperationFailure>;
    fn authenticate_original_envelope(
        &self,
        envelope: &crucible_node_transport::envelope::Envelope,
        direction: FrameDirection,
        index: usize,
    ) -> Result<(), OperationFailure>;
}

struct LiveTranscript<'a> {
    controller: &'a CnpController,
    history: OriginalNative5FrameHistory<'a>,
}

impl TranscriptState for LiveTranscript<'_> {
    fn original(&self, id: &Id) -> Option<&ClientOriginal> {
        self.controller.original(id)
    }
    fn originals_by_origin(&self, origin: RequestOrigin) -> impl Iterator<Item = &ClientOriginal> {
        self.controller.originals_by_origin(origin)
    }
    fn content(&self, reference: &ContentRef) -> Result<&[u8], OperationFailure> {
        self.controller.content(reference).map_err(unknown)
    }
    fn frames(&self) -> Result<impl Iterator<Item = OriginalFrame<'_>>, OperationFailure> {
        self.history.frames().map_err(unknown)
    }
    fn authenticate_original_envelope(
        &self,
        envelope: &crucible_node_transport::envelope::Envelope,
        direction: FrameDirection,
        index: usize,
    ) -> Result<(), OperationFailure> {
        self.history
            .authenticate_original_envelope(envelope, direction, index)
            .map_err(unknown)
    }
}

impl TranscriptState for HistoricalControllerState {
    fn original(&self, id: &Id) -> Option<&ClientOriginal> {
        self.custody.controller.get(id)
    }
    fn originals_by_origin(&self, origin: RequestOrigin) -> impl Iterator<Item = &ClientOriginal> {
        match origin {
            RequestOrigin::Controller => self.custody.controller.values(),
            RequestOrigin::Provider => self.custody.provider.values(),
        }
    }
    fn content(&self, reference: &ContentRef) -> Result<&[u8], OperationFailure> {
        self.custody.content.get(reference).map_err(unknown)
    }
    fn frames(&self) -> Result<impl Iterator<Item = OriginalFrame<'_>>, OperationFailure> {
        Ok(self.original_frames_data())
    }
    fn authenticate_original_envelope(
        &self,
        envelope: &crucible_node_transport::envelope::Envelope,
        direction: FrameDirection,
        index: usize,
    ) -> Result<(), OperationFailure> {
        self.authenticate_original_envelope_data(envelope, direction, index)
            .map_err(unknown)
    }
}

fn verify_transcript(
    controller: &impl TranscriptState,
    confirmation_request: &Id,
    receipt: &PacketNativeAfterConfirmationReceipt,
) -> Result<(), OperationFailure> {
    receipt.validate_data().map_err(unknown)?;
    let context = &receipt.capture;
    if confirmation_request == &context.capture_request_id {
        return Err(refused("Capture transcript reuses confirmation request"));
    }
    let capture = controller
        .original(&context.capture_request_id)
        .ok_or_else(|| refused("Capture transcript original absent"))?;
    let poll = controller
        .original(confirmation_request)
        .ok_or_else(|| refused("Capture transcript confirmation absent"))?;
    let terminal = capture
        .response
        .as_ref()
        .ok_or_else(|| refused("Capture transcript terminal unresolved"))?;
    let poll_terminal = poll
        .response
        .as_ref()
        .ok_or_else(|| refused("Capture transcript confirmation unresolved"))?;
    capture
        .request
        .matches_response(terminal)
        .map_err(unknown)?;
    poll.request
        .matches_response(poll_terminal)
        .map_err(unknown)?;
    if capture.identity != context.capture_request_hash
        || capture.request.method != Method::Begin
        || poll.request.method != Method::Poll
        || capture.request.operation_id.0.as_ref() != Some(&context.capture_operation_id)
        || poll.request.operation_id != capture.request.operation_id
        || poll.request.capture_owner_id != capture.request.capture_owner_id
        || terminal.sequence != context.capture_terminal_sequence
        || poll.request.extensions.len() != 1
        || poll_terminal.extensions.len() != 1
    {
        return Err(refused("Capture transcript original context differs"));
    }
    let retained: PacketNativeAfterConfirmationReceipt = serde::Deserialize::deserialize(
        poll_terminal
            .extensions
            .get(PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION)
            .ok_or_else(|| refused("Capture transcript confirmation extension absent"))?,
    )
    .map_err(unknown)?;
    let requested: crucible_node_transport::reference_packet::service::confirmation::PacketNativeAfterConfirmationRequest =
        serde::Deserialize::deserialize(poll.request.extensions
            .get(PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION)
            .ok_or_else(|| refused("Capture transcript request extension absent"))?)
            .map_err(unknown)?;
    if &retained != receipt || requested != *context {
        return Err(refused(
            "Capture transcript extension differs from retained receipt",
        ));
    }
    let capture_body =
        decode_request(capture.request.method, &capture.request.body).map_err(unknown)?;
    let result = decode_response(&capture_body, &terminal.body).map_err(unknown)?;
    let Some(MethodResult::Capture(result)) = completed_result(result)? else {
        return Err(refused("Capture transcript terminal has no Capture result"));
    };
    if result.capture_manifest != context.native_snapshot_ref
        || result.owner_state_refs.as_slice() != std::slice::from_ref(&context.native_control_ref)
        || result.unchanged_cut_receipt != context.native_anchor_ref
    {
        return Err(refused("Capture transcript three object references differ"));
    }
    let poll_body = decode_request(poll.request.method, &poll.request.body).map_err(unknown)?;
    let result = decode_response(&poll_body, &poll_terminal.body).map_err(unknown)?;
    let Some(MethodResult::Poll(result)) = completed_result(result)? else {
        return Err(refused("Capture transcript terminal has no Poll result"));
    };
    if result.operation_id != context.capture_operation_id
        || !result.observations.is_empty()
        || result.next_observation_sequence.get() != 0
        || result.outcome.0.as_ref() != Some(&terminal.body)
    {
        return Err(refused("Capture transcript Poll changed original outcome"));
    }

    let references = [
        &context.native_snapshot_ref,
        &context.native_anchor_ref,
        &context.native_control_ref,
        &receipt.native_after_ref,
    ];
    for reference in references {
        reference
            .verify(controller.content(reference)?)
            .map_err(unknown)?;
    }
    let mut phase = 0u8;
    let mut next = [None; 2];
    let mut frames = 0usize;
    let mut transfers = [Transfer::default(); 4];
    let mut pending_ack: Option<&Id> = None;
    for (index, frame) in controller.frames()?.enumerate() {
        if frame.bytes.len() < 4 || !frame.complete || frame.transferred != frame.bytes.len() {
            return Err(refused("Capture transcript contains partial literal I/O"));
        }
        let header: BorrowedHeader<'_> =
            serde_json::from_slice(&frame.bytes[4..]).map_err(unknown)?;
        let request_id = header
            .request_id
            .ok_or_else(|| refused("Capture transcript event unsupported"))?;
        let sequence = header.sequence.parse::<u64>().map_err(unknown)?;
        let direction = usize::from(frame.direction == FrameDirection::Outgoing);
        if next[direction].is_some_and(|expected| sequence != expected) {
            return Err(refused("Capture transcript sequence repeats or skips"));
        }
        next[direction] = Some(
            sequence
                .checked_add(1)
                .ok_or_else(|| refused("Capture transcript sequence overflow"))?,
        );
        let origin = match (frame.direction, header.message) {
            (FrameDirection::Outgoing, MessageKind::Request)
            | (FrameDirection::Incoming, MessageKind::Response) => RequestOrigin::Controller,
            (FrameDirection::Incoming, MessageKind::Request)
            | (FrameDirection::Outgoing, MessageKind::Response) => RequestOrigin::Provider,
            _ => return Err(refused("Capture transcript unsolicited frame unsupported")),
        };
        let original = controller
            .originals_by_origin(origin)
            .find(|one| {
                one.request
                    .request_id
                    .0
                    .as_ref()
                    .is_some_and(|id| id.as_str() == request_id)
            })
            .ok_or_else(|| refused("Capture transcript literal has no typed original"))?;
        let envelope = match header.message {
            MessageKind::Request => &original.request,
            MessageKind::Response => original
                .response
                .as_ref()
                .ok_or_else(|| refused("Capture transcript original response unresolved"))?,
            _ => return Err(refused("Capture transcript frame kind unsupported")),
        };
        if envelope.sequence.get() != sequence {
            return Err(refused("Capture transcript assigned sequence differs"));
        }
        controller.authenticate_original_envelope(envelope, frame.direction, index)?;
        frames = frames
            .checked_add(1)
            .ok_or_else(|| refused("Capture transcript count overflow"))?;

        // The actual native publisher waits for each exact proof ACK before
        // sending its next frame. A completed typed response alone cannot stand
        // for that literal ACK having occurred before a terminal/window edge.
        if pending_ack.is_some()
            && (origin != RequestOrigin::Provider || header.message != MessageKind::Response)
        {
            return Err(refused(
                "Capture proof request precedes the previous literal ACK",
            ));
        }
        if origin == RequestOrigin::Controller && request_id == context.capture_request_id.as_str()
        {
            phase = match (phase, header.message) {
                (0, MessageKind::Request) => 1,
                (1, MessageKind::Response) if transfers[..3].iter().all(|one| one.finished) => {
                    if canonical::hash(
                        "source-owned.packet-native-capture-terminal/5",
                        &frame.bytes[4..],
                    )
                    .map_err(unknown)?
                        != context.capture_terminal_hash
                    {
                        return Err(refused("Capture transcript actual terminal hash differs"));
                    }
                    2
                }
                _ => {
                    return Err(refused(
                        "Capture transcript terminal precedes complete ACK prefix",
                    ));
                }
            };
        } else if origin == RequestOrigin::Controller && request_id == confirmation_request.as_str()
        {
            phase = match (phase, header.message) {
                (2, MessageKind::Request) => 3,
                (3, MessageKind::Response) if transfers[3].finished => 4,
                _ => return Err(refused("Capture transcript Poll boundary differs")),
            };
        } else if phase != 0 {
            if phase == 4 || origin != RequestOrigin::Provider || !matches!(phase, 1 | 3) {
                return Err(refused(
                    "Capture transcript contains an unrelated suffix frame",
                ));
            }
            if header.message == MessageKind::Request {
                let prefix = match phase {
                    1 => "packet-capture-proof-",
                    3 => "packet-after-proof-",
                    _ => return Err(refused("Capture proof phase is unavailable")),
                };
                if !counter_id_matches(request_id, prefix, sequence) {
                    return Err(refused(
                        "Capture proof request ID differs from assigned writer sequence",
                    ));
                }
                verify_transfer(controller, original, phase, references, &mut transfers)?;
                pending_ack = original.request.request_id.0.as_ref();
            } else {
                if !pending_ack.is_some_and(|id| id.as_str() == request_id) {
                    return Err(refused("Capture proof literal ACK has no current request"));
                }
                let transfer = original
                    .request
                    .body
                    .get("transfer_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| refused("Capture proof ACK transfer identity absent"))?;
                if !matches!(
                    original.request.method,
                    Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
                ) || !transfers
                    .iter()
                    .enumerate()
                    .any(|(index, one)| one.id == Some(transfer) && (phase == 1) == (index < 3))
                {
                    return Err(refused("Capture proof ACK belongs to another transfer"));
                }
                pending_ack = None;
            }
        }
    }
    let originals = controller
        .originals_by_origin(RequestOrigin::Controller)
        .count()
        .checked_add(
            controller
                .originals_by_origin(RequestOrigin::Provider)
                .count(),
        )
        .and_then(|count| count.checked_mul(2))
        .ok_or_else(|| refused("Capture transcript original population overflow"))?;
    if phase != 4
        || pending_ack.is_some()
        || frames != originals
        || !transfers.iter().all(|one| one.finished)
    {
        return Err(refused("Capture transcript is not fully exhausted"));
    }
    let _ = controller.frames()?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct BorrowedHeader<'a> {
    message: MessageKind,
    #[serde(borrow)]
    request_id: Option<&'a str>,
    #[serde(borrow)]
    sequence: &'a str,
}

#[derive(Clone, Copy, Default)]
struct Transfer<'a> {
    id: Option<&'a str>,
    offset: usize,
    maximum_chunk: usize,
    finished: bool,
}

fn verify_transfer<'a>(
    controller: &impl TranscriptState,
    original: &'a ClientOriginal,
    phase: u8,
    references: [&ContentRef; 4],
    transfers: &mut [Transfer<'a>; 4],
) -> Result<(), OperationFailure> {
    let request = &original.request;
    let response = original
        .response
        .as_ref()
        .ok_or_else(|| refused("Capture proof acknowledgement absent"))?;
    request.matches_response(response).map_err(unknown)?;
    if !request.extensions.is_empty() || !response.extensions.is_empty() {
        return Err(refused("Capture proof carries unexpected extensions"));
    }
    let transfer_id = request
        .body
        .get("transfer_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| refused("Capture proof transfer identity absent"))?;
    let body = decode_request(request.method, &request.body).map_err(unknown)?;
    let result = completed_result(decode_response(&body, &response.body).map_err(unknown)?)?;
    match (&body, result) {
        (RequestBody::BlobBegin(begin), Some(MethodResult::BlobBegin(ack))) => {
            let index = references
                .iter()
                .position(|one| **one == begin.content)
                .ok_or_else(|| refused("Capture proof transfers an unrelated object"))?;
            let prefix = if phase == 1 {
                "packet-capture-transfer-"
            } else {
                "packet-after-transfer-"
            };
            if !next_object_window(transfers, phase, index)
                || !counter_id_matches(transfer_id, prefix, request.sequence.get())
                || transfers[index].id.is_some()
                || transfers.iter().any(|one| one.id == Some(transfer_id))
                || !begin.extensions.is_empty()
                || ack.transfer_id != begin.transfer_id
                || ack.next_offset.get() != 0
                || ack.maximum_chunk_bytes.get() == 0
            {
                return Err(refused(
                    "Capture proof Begin differs from selected object window",
                ));
            }
            transfers[index].id = Some(transfer_id);
            transfers[index].maximum_chunk = usize::try_from(ack.maximum_chunk_bytes.get())
                .map_err(|_| refused("Capture proof chunk allowance is not representable"))?;
        }
        (RequestBody::BlobChunk(chunk), Some(MethodResult::BlobChunk(ack))) => {
            let index = transfer_index(transfers, transfer_id, phase)?;
            let state = &mut transfers[index];
            let bytes = controller.content(references[index])?;
            let end = state
                .offset
                .checked_add(chunk.bytes.as_slice().len())
                .filter(|end| *end <= bytes.len())
                .ok_or_else(|| refused("Capture proof chunk exceeds actual content"))?;
            if chunk.bytes.as_slice().is_empty()
                || !chunk.extensions.is_empty()
                || chunk.offset.get() != state.offset as u64
                || chunk.bytes.as_slice().len() > state.maximum_chunk
                || chunk.bytes.as_slice() != &bytes[state.offset..end]
                || ack.transfer_id != chunk.transfer_id
                || ack.next_offset.get() != end as u64
            {
                return Err(refused("Capture proof chunk or acknowledgement differs"));
            }
            state.offset = end;
        }
        (RequestBody::BlobFinish(finish), Some(MethodResult::BlobFinish(ack))) => {
            let index = transfer_index(transfers, transfer_id, phase)?;
            if !finish.extensions.is_empty()
                || ack.transfer_id != finish.transfer_id
                || ack.content != *references[index]
                || transfers[index].offset != controller.content(references[index])?.len()
            {
                return Err(refused(
                    "Capture proof Finish precedes complete byte custody",
                ));
            }
            transfers[index].finished = true;
        }
        _ => {
            return Err(refused(
                "Capture proof has an unsupported request or acknowledgement",
            ));
        }
    }
    Ok(())
}

// Native Capture emits snapshot, anchor and Control as complete sequential
// windows. Confirmation emits its distinct fourth window only after Poll.
fn next_object_window(transfers: &[Transfer<'_>; 4], phase: u8, index: usize) -> bool {
    match phase {
        1 => index < 3 && transfers[..3].iter().position(|one| !one.finished) == Some(index),
        3 => index == 3 && transfers[..3].iter().all(|one| one.finished) && !transfers[3].finished,
        _ => false,
    }
}

fn counter_id_matches(id: &str, prefix: &str, sequence: u64) -> bool {
    let Some(decimal) = id.strip_prefix(prefix) else {
        return false;
    };
    !decimal.is_empty()
        && (decimal == "0" || !decimal.starts_with('0'))
        && decimal.bytes().all(|byte| byte.is_ascii_digit())
        && decimal.parse::<u64>() == Ok(sequence)
}

fn transfer_index(
    transfers: &[Transfer<'_>; 4],
    id: &str,
    phase: u8,
) -> Result<usize, OperationFailure> {
    transfers
        .iter()
        .enumerate()
        .position(|(index, one)| one.id == Some(id) && !one.finished && (phase == 1) == (index < 3))
        .ok_or_else(|| refused("Capture proof transfer is absent, finished or in another window"))
}

fn completed_result(
    response: crucible_node_transport::bodies::ResponseBody,
) -> Result<Option<MethodResult>, OperationFailure> {
    if !matches!(response.shape, ResponseShape::Completed { ref extensions, .. } if extensions.is_empty())
    {
        return Err(refused(
            "Capture transcript response is not a closed completed result",
        ));
    }
    Ok(response.result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_ids_use_actual_envelope_sequence_and_distinct_phase_prefix() {
        assert!(counter_id_matches(
            "packet-capture-proof-27",
            "packet-capture-proof-",
            27
        ));
        assert!(!counter_id_matches(
            "packet-capture-proof-27",
            "packet-capture-proof-",
            8
        ));
        for id in [
            "packet-capture-proof-027",
            "packet-capture-proof-+27",
            "packet-after-proof-27",
        ] {
            assert!(!counter_id_matches(id, "packet-capture-proof-", 27));
        }
        assert!(counter_id_matches(
            "packet-after-proof-27",
            "packet-after-proof-",
            27
        ));
        assert!(counter_id_matches(
            "packet-after-transfer-18446744073709551615",
            "packet-after-transfer-",
            u64::MAX
        ));
        assert!(!counter_id_matches(
            "packet-after-transfer-18446744073709551616",
            "packet-after-transfer-",
            0
        ));
    }

    #[test]
    fn native_objects_cannot_skip_or_interleave_the_original_complete_windows() {
        let mut transfers = [Transfer::default(); 4];
        assert!(next_object_window(&transfers, 1, 0));
        assert!(!next_object_window(&transfers, 1, 1));
        assert!(!next_object_window(&transfers, 3, 3));

        transfers[0].finished = true;
        assert!(next_object_window(&transfers, 1, 1));
        assert!(!next_object_window(&transfers, 1, 2));
        transfers[1].finished = true;
        transfers[2].finished = true;
        assert!(next_object_window(&transfers, 3, 3));
        assert!(!next_object_window(&transfers, 1, 0));
        transfers[3].finished = true;
        assert!(!next_object_window(&transfers, 3, 3));
    }
}
