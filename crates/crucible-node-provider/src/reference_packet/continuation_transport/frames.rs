//! Precharges complete Capture frames before registering any transport window.

use super::*;
use crucible_node_contract::{Bytes, Extensions, U64, Validate};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::handshake::ConnectionAuthority;

pub(super) struct CapturePlan {
    pub windows: VecDeque<Vec<Envelope>>,
    pub contents: BTreeMap<Id, ContentRef>,
    pub chunk: u64,
    pub charged_bytes: usize,
    pub next_sequence: u64,
}

pub(super) fn plan(
    authority: &ConnectionAuthority,
    source: &CaptureSource,
) -> Result<CapturePlan, ProviderError> {
    let response = &source.response;
    if response.message != MessageKind::Response
        || response.method != Method::Begin
        || response.capture_owner_id.0.is_none()
        || response.operation_id.0.is_none()
        || response.request_id.0.is_none()
        || response.session_id.0.as_ref() != Some(authority.session_id())
        || response.incarnation_id.0.as_ref() != Some(authority.incarnation_id())
        || !response.extensions.is_empty()
    {
        return Err(ProviderError::Correlation(
            "capture prefix original reply scope",
        ));
    }
    let maximum_frame = usize::try_from(authority.limits().frame_bytes.get())
        .map_err(|_| ProviderError::ResourceExhausted("capture frame ceiling"))?;
    if maximum_frame > 65_536 {
        return Err(ProviderError::ResourceExhausted(
            "capture negotiated frame ceiling",
        ));
    }
    crate::connection::serialized_credit(response, maximum_frame)?;
    let ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result,
        extensions,
    } = crate::bodies::decode_response_shape(&response.body)?
    else {
        return Err(ProviderError::Correlation(
            "capture prefix requires completed Capture",
        ));
    };
    if !extensions.is_empty() {
        return Err(ProviderError::Correlation(
            "capture prefix result extensions",
        ));
    }
    let capture: CaptureResult = serde_json::from_value(Value::Object(result))
        .map_err(crucible_node_contract::ContractError::from)?;
    capture.validate()?;
    if capture.capture_manifest != source.snapshot.0
        || capture.unchanged_cut_receipt != source.anchor.0
        || source.snapshot.0 == source.anchor.0
        || source.snapshot.1.len() > MAXIMUM_CAPTURE_SNAPSHOT_BYTES
        || source.anchor.1.len() > MAXIMUM_CAPTURE_ANCHOR_BYTES
    {
        return Err(ProviderError::ResourceExhausted(
            "capture snapshot/anchor closure",
        ));
    }
    source.snapshot.0.verify(&source.snapshot.1)?;
    source.anchor.0.verify(&source.anchor.1)?;
    let chunk = usize::try_from(authority.limits().blob_chunk_bytes.get())
        .map_err(|_| ProviderError::ResourceExhausted("capture chunk ceiling"))?
        .min(4096);
    let simultaneous = usize::try_from(authority.limits().requests.get())
        .map_err(|_| ProviderError::ResourceExhausted("capture correlation ceiling"))?
        .min(MAXIMUM_CAPTURE_WINDOW_REQUESTS);
    if chunk == 0 || simultaneous == 0 {
        return Err(ProviderError::ResourceExhausted(
            "capture finite transport credit",
        ));
    }
    let count = [source.snapshot.1.len(), source.anchor.1.len()]
        .into_iter()
        .try_fold(1usize, |total, length| {
            total.checked_add(2 + length.div_ceil(chunk))
        })
        .filter(|count| *count <= 4096)
        .ok_or(ProviderError::ResourceExhausted(
            "capture whole frame population",
        ))?;
    let next_sequence = response.sequence.get().checked_add(count as u64).ok_or(
        ProviderError::ResourceExhausted("capture provider sequence overflow"),
    )?;
    // Reserve the whole bounded frame population before copying any proof body.
    // Each prospective frame is charged before it enters this retained plan.
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(count)
        .map_err(|_| ProviderError::ResourceExhausted("capture original frame slots"))?;
    let mut charged_bytes = 0usize;
    append(
        &mut frames,
        &mut charged_bytes,
        maximum_frame,
        response.clone(),
    )?;
    let mut sequence = response.sequence.get() + 1;
    let mut contents = BTreeMap::new();
    for (reference, bytes) in [&source.snapshot, &source.anchor] {
        let transfer = Id::new(format!("packet-capture-transfer-{sequence}"))?;
        contents.insert(transfer.clone(), reference.clone());
        append_request(
            &mut frames,
            &mut charged_bytes,
            maximum_frame,
            authority,
            &mut sequence,
            Method::BlobBegin,
            object(BlobBeginRequest {
                transfer_id: transfer.clone(),
                content: reference.clone(),
                extensions: Extensions::new(),
            })?,
        )?;
        for (index, bytes) in bytes.chunks(chunk).enumerate() {
            append_request(
                &mut frames,
                &mut charged_bytes,
                maximum_frame,
                authority,
                &mut sequence,
                Method::BlobChunk,
                object(BlobChunkRequest {
                    transfer_id: transfer.clone(),
                    offset: U64::new((index * chunk) as u64),
                    bytes: Bytes::new(bytes.to_vec()),
                    extensions: Extensions::new(),
                })?,
            )?;
        }
        append_request(
            &mut frames,
            &mut charged_bytes,
            maximum_frame,
            authority,
            &mut sequence,
            Method::BlobFinish,
            object(BlobFinishRequest {
                transfer_id: transfer,
                extensions: Extensions::new(),
            })?,
        )?;
    }
    if sequence != next_sequence {
        return Err(ProviderError::Conflict(
            "capture complete sequence accounting",
        ));
    }
    let window_count = (count - 1).div_ceil(simultaneous);
    let mut windows = VecDeque::new();
    windows
        .try_reserve_exact(window_count)
        .map_err(|_| ProviderError::ResourceExhausted("capture window slots"))?;
    let mut window = Vec::new();
    window
        .try_reserve_exact(simultaneous + 1)
        .map_err(|_| ProviderError::ResourceExhausted("capture window frame slots"))?;
    let mut requests = 0usize;
    for frame in frames {
        if frame.message == MessageKind::Request && requests == simultaneous {
            windows.push_back(window);
            window = Vec::new();
            window
                .try_reserve_exact(simultaneous)
                .map_err(|_| ProviderError::ResourceExhausted("capture window frame slots"))?;
            requests = 0;
        }
        requests += usize::from(frame.message == MessageKind::Request);
        window.push(frame);
    }
    if !window.is_empty() {
        windows.push_back(window);
    }
    Ok(CapturePlan {
        windows,
        contents,
        chunk: chunk as u64,
        charged_bytes,
        next_sequence,
    })
}

fn append(
    frames: &mut Vec<Envelope>,
    charge: &mut usize,
    maximum_frame: usize,
    frame: Envelope,
) -> Result<(), ProviderError> {
    let encoded = crate::connection::serialized_credit(&frame, maximum_frame)?;
    let replies = if frame.message == MessageKind::Request {
        maximum_frame * 2
    } else {
        0
    };
    *charge = encoded
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(replies))
        .and_then(|bytes| charge.checked_add(bytes))
        .filter(|bytes| *bytes <= MAXIMUM_CAPTURE_TRANSPORT_BYTES)
        .ok_or(ProviderError::ResourceExhausted(
            "capture whole encoded transport credit",
        ))?;
    frames.push(frame);
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Couples one original frame to its same whole-prefix charge and sequence.
fn append_request(
    frames: &mut Vec<Envelope>,
    charge: &mut usize,
    maximum_frame: usize,
    authority: &ConnectionAuthority,
    sequence: &mut u64,
    method: Method,
    body: Map<String, Value>,
) -> Result<(), ProviderError> {
    let frame = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(authority.session_id().clone())),
        incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        operation_id: Nullable(None),
        request_id: Nullable(Some(Id::new(format!("packet-capture-proof-{sequence}"))?)),
        sequence: U64::new(*sequence),
        method,
        body,
        extensions: Extensions::new(),
    };
    append(frames, charge, maximum_frame, frame)?;
    *sequence = sequence
        .checked_add(1)
        .ok_or(ProviderError::ResourceExhausted(
            "capture original sequence overflow",
        ))?;
    Ok(())
}

fn object(value: impl Serialize) -> Result<Map<String, Value>, ProviderError> {
    match serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)? {
        Value::Object(value) => Ok(value),
        _ => Err(ProviderError::Frame("capture frame body must be object")),
    }
}
