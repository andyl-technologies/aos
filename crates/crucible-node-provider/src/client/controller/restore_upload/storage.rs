//! Quotes the concrete new upload owners and complete ordinary protocol phases.
//!
//! All byte bodies remain borrowed from the Source's independently counted
//! immutable ticket. This DATA row does not price arbitrary erased callbacks,
//! Source signing, native decode/model/Commit or existing whole controller roots.

use super::*;
use crate::retained_metadata::{
    requested_metadata_backing_storage_data as backing,
    requested_storage::tree_storage_data,
    serialization_storage::{
        OriginalSerializationStorageData as Data,
        OriginalSerializationStorageProjection as Projection,
        original_serialization_counter_scratch_data,
    },
};
use std::mem::{align_of, size_of};

pub(super) struct Parts {
    pub(super) chunk: usize,
    pub(super) requests: usize,
    pub(super) retained: usize,
    pub(super) transient: usize,
}

pub(in crate::client::controller) fn counter_scratch_data() -> usize {
    size_of::<Parts>() + size_of::<OriginalCompleteRestoreInputUploadStorageData>()
        + size_of::<OriginalProtocolStorageFacts>()
        + size_of::<OriginalCompleteRestoreInputUpload>() + size_of::<UploadFrame>()
        + size_of::<UploadExecution<'static>>()
        + size_of::<PrepareInputs<'static>>() + size_of::<inputs::Reference<'static>>()
        + size_of::<[&[u8]; 6]>() + size_of::<[usize; 6]>()
        + 2 * size_of::<MetadataObserver<'static>>() + 2 * size_of::<RetainedProtocolMetadataFacts>()
        + 3 * size_of::<Data>() + size_of::<Projection>()
        + size_of::<&inputs::Reference<'static>>()
        + size_of::<Result<Data, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + original_serialization_counter_scratch_data()
        + size_of::<ReceivedFrame>() + size_of::<ResponseBody>() + size_of::<RequestBody>()
        + size_of::<OperationalDeadline>() + size_of::<Rc<ProtocolCaptureOwner>>()
        + 2 * size_of::<CompleteRestoreTransferProjection<'static>>()
        + size_of::<BlobBeginRequest>() + size_of::<BlobChunkRequest>() + size_of::<BlobFinishRequest>()
        + size_of::<NotificationBody>() + size_of::<Value>() + size_of::<std::fmt::Arguments<'static>>()
        // Exact normative CNP domain/payload-length framing banks.
        + size_of::<[u8; 4]>() + size_of::<[u8; 8]>()
        + size_of::<blake3::Hasher>() + size_of::<blake3::Hash>()
        + std::mem::size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex())
        + size_of::<(&Envelope, &ContentRef, &Id, &Value)>()
        + size_of::<std::ops::Range<usize>>() + size_of::<std::array::IntoIter<Method, 3>>()
        + size_of::<std::slice::Iter<'static, inputs::Reference<'static>>>()
        + size_of::<std::collections::btree_map::Keys<'static, Id, super::super::super::ClientOriginal>>()
        // Actual object-name slices/iterator and runtime aggregation banks.
        + size_of::<[&str; 13]>() + size_of::<[&str; 4]>() + size_of::<[&str; 3]>()
        + size_of::<&[&str]>() + size_of::<std::slice::Iter<'static, &'static str>>()
        + 2 * size_of::<[usize; 7]>() + size_of::<[usize; 9]>()
        + size_of::<[usize; 5]>() + size_of::<[usize; 3]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<std::num::ParseIntError>() + size_of::<std::str::Bytes<'static>>()
        + 12 * size_of::<usize>()
}

pub(super) fn quote(
    controller: &CnpController,
    inputs: &PrepareInputs<'_>,
    maximum: usize,
) -> Result<Parts, ProviderError> {
    quote_references(controller, &inputs.references, inputs.prefix(), 0, maximum)
}

pub(super) fn quote_references(
    controller: &CnpController,
    references: &[inputs::Reference<'_>; 6],
    prefix: blake3::Hash,
    preceding_pairs: usize,
    maximum: usize,
) -> Result<Parts, ProviderError> {
    let frame_maximum = controller.maximum_frame()?;
    let negotiated_chunk = usize::try_from(controller.authority().limits().blob_chunk_bytes.get())
        .map_err(|_| credit())?;
    let chunk = negotiated_chunk
        .min(4096)
        .min(frame_maximum.saturating_sub(4096).saturating_mul(3) / 4);
    if chunk == 0 {
        return Err(credit());
    }
    let mut requests = 0usize;
    for reference in references {
        requests = add(requests, add(reference.length.div_ceil(chunk), 2)?)?;
    }
    let prefix = prefix.to_hex();
    // All selected IDs share this cryptographic actual-Prepare prefix. Existing
    // cached IDs with that prefix conservatively refuse before any ID allocation.
    if controller
        .custody
        .has_original_restore_upload_prefix(prefix.as_str())
    {
        return Err(refused());
    }
    let cache = controller
        .custody
        .fresh_query_cache_requested_layout_data(add(requests, preceding_pairs)?)?;
    let mut retained = sum(&[
        size_of::<OriginalCompleteRestoreInputUpload>(),
        size_of::<OriginalCompleteRestoreInputUploadStorageData>(),
        mul(requests, size_of::<UploadFrame>())?,
        mul(requests, growth(128)?)?,
        mul(6, growth(128)?)?,
        cache,
        // One actual pending-guard tree can retain its root after a completed ACK.
        tree_storage_data(
            1,
            1,
            size_of::<Id>() + size_of::<Envelope>(),
            align_of::<Envelope>().max(align_of::<Id>()),
        )?,
    ])?;
    let mut association = MetadataObserver::new();
    association.shared_value(controller.protocol_owner.as_ref())?;
    retained = add(retained, backing(&association.finish())?)?;
    let raw_receive =
        crate::connection::original_host_initial_raw_receive_storage_data(frame_maximum)?;
    // One final foreign/error response may retain the full raw-R owner while
    // successful closed responses already live in the immutable upload history.
    retained = add(
        retained,
        sum(&[
            raw_receive,
            size_of::<RequestBody>(),
            size_of::<NotificationBody>(),
        ])?,
    )?;
    let mut work = 0usize;
    let mut literal = 0usize;
    for reference in references {
        retained = add(retained, reference.cloned_reference_storage_data()?)?;
        for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
            let count = if method == Method::BlobChunk {
                reference.length.div_ceil(chunk)
            } else {
                1
            };
            let request = frame(controller, reference, method, false, chunk)?;
            let response = frame(controller, reference, method, true, chunk)?;
            if request.maximum_encoded_bytes > frame_maximum
                || response.maximum_encoded_bytes > frame_maximum
            {
                return Err(credit());
            }
            // Independent full request owners: upload ledger + ClientOriginal.
            // Independent response views: upload Envelope + ClientOriginal +
            // raw ResponseShape result + separately decoded Blob method result.
            retained = add(
                retained,
                mul(
                    count,
                    sum(&[
                        mul(2, request.dom_and_canonical_scratch_bytes)?,
                        mul(4, response.dom_and_canonical_scratch_bytes)?,
                        size_of::<ResponseBody>(),
                        // Cache map key, original request identity and its three strings.
                        growth(128)?,
                        growth(64)?,
                        growth("cnp.request.v1".len())?,
                        growth("blake3-256".len())?,
                    ])?,
                )?,
            )?;
            literal = add(
                literal,
                mul(count, add(request.maximum_encoded_bytes, frame_maximum)?)?,
            )?;
            // Sum all phases rather than refunding allocation slack. These are
            // real request/response DOM/parser/canonical/clone/hash operations.
            work = add(
                work,
                mul(
                    count,
                    sum(&[
                        request.requested_total()?,
                        response.requested_total()?,
                        request.dom_and_canonical_scratch_bytes, // pending correlation clone
                        request.requested_total()?,              // original identity projection
                        growth(128)?,                            // bounded actual ID format! bank
                        growth(chunk)?, // actual typed chunk Vec before base64
                        growth(chunk.div_ceil(3).checked_mul(4).ok_or_else(credit)?)?,
                        size_of::<RequestBody>(),
                        size_of::<Envelope>(),
                    ])?,
                )?,
            )?;
        }
    }
    let pairs = add(requests, preceding_pairs)?;
    let literal = add(literal, mul(mul(preceding_pairs, 2)?, frame_maximum)?)?;
    let framing = mul(pairs, 8)?;
    let frontier = controller.original_native5_storage_facts()?;
    if !frontier.all_io_complete
        || add(frontier.incoming_frames, pairs)? > frontier.maximum_frames_per_direction
        || add(frontier.outgoing_frames, pairs)? > frontier.maximum_frames_per_direction
        || add(
            add(frontier.incoming_frames, frontier.outgoing_frames)?,
            mul(pairs, 2)?,
        )? > frontier.descriptor_capacity
        || add(frontier.retained_bytes, add(literal, framing)?)? > frontier.maximum_history_bytes
        || add(frontier.retained_bytes, add(literal, framing)?)? > frontier.byte_capacity
    {
        return Err(credit());
    }
    controller.preflight_source_reply(pairs, 0, literal, 0, 0)?;
    let transient = sum(&[
        work,
        raw_receive,
        size_of::<ReceivedFrame>(),
        size_of::<ResponseBody>(),
        size_of::<RequestBody>(),
    ])?;
    if sum(&[retained, transient, counter_scratch_data()])? > maximum {
        return Err(credit());
    }
    Ok(Parts {
        chunk,
        requests,
        retained,
        transient,
    })
}

fn frame(
    controller: &CnpController,
    reference: &inputs::Reference<'_>,
    method: Method,
    response: bool,
    chunk: usize,
) -> Result<Data, ProviderError> {
    frame_with_reference(controller, method, response, chunk, |projection| {
        reference.project(projection)
    })
}

// The held prefix has a different, fixed worst-case serializable reference.
// Share the real envelope grammar without pretending it is an upload input.
pub(in crate::client::controller) fn held_prefix_frame(
    controller: &CnpController,
    reference: &impl serde::Serialize,
    method: Method,
    response: bool,
    chunk: usize,
) -> Result<Data, ProviderError> {
    frame_with_reference(controller, method, response, chunk, |projection| {
        projection.add_value(reference)
    })
}

// Both concrete adapters project directly into this same counting sink. No
// reference is cloned or serialized into an owned intermediate Value.
fn frame_with_reference(
    controller: &CnpController,
    method: Method,
    response: bool,
    chunk: usize,
    project_reference: impl Fn(&mut Projection) -> Result<(), ProviderError>,
) -> Result<Data, ProviderError> {
    let mut p = Projection::new(usize::MAX)?;
    object(
        &mut p,
        &[
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "operation_id",
            "request_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ],
    )?;
    p.add_string("CNP/1")?;
    p.add_value(&if response {
        MessageKind::Response
    } else {
        MessageKind::Request
    })?;
    p.add_value(controller.authority().session_id())?;
    p.add_value(controller.authority().incarnation_id())?;
    for _ in 0..4 {
        p.add_value(&())?;
    }
    p.add_unescaped_ascii_extent(128)?;
    p.add_unescaped_ascii_extent(20)?;
    p.add_value(&method)?;
    if response {
        object(
            &mut p,
            &["status", "operation_state", "result", "extensions"],
        )?;
        p.add_string("completed")?;
        p.add_value(&OperationState::Completed)?;
    }
    match (method, response) {
        (Method::BlobBegin, false) => {
            object(&mut p, &["transfer_id", "content", "extensions"])?;
            p.add_unescaped_ascii_extent(128)?;
            project_reference(&mut p)?;
            p.add_object()?;
        }
        (Method::BlobBegin, true) => {
            object(
                &mut p,
                &["transfer_id", "next_offset", "maximum_chunk_bytes"],
            )?;
            p.add_unescaped_ascii_extent(128)?;
            p.add_unescaped_ascii_extent(20)?;
            p.add_unescaped_ascii_extent(20)?;
        }
        (Method::BlobChunk, false) => {
            object(&mut p, &["transfer_id", "offset", "bytes", "extensions"])?;
            p.add_unescaped_ascii_extent(128)?;
            p.add_unescaped_ascii_extent(20)?;
            p.add_unescaped_ascii_extent(chunk.div_ceil(3).checked_mul(4).ok_or_else(credit)?)?;
            p.add_object()?;
        }
        (Method::BlobChunk, true) => {
            object(&mut p, &["transfer_id", "next_offset"])?;
            p.add_unescaped_ascii_extent(128)?;
            p.add_unescaped_ascii_extent(20)?;
        }
        (Method::BlobFinish, false) => {
            object(&mut p, &["transfer_id", "extensions"])?;
            p.add_unescaped_ascii_extent(128)?;
            p.add_object()?;
        }
        (Method::BlobFinish, true) => {
            object(&mut p, &["transfer_id", "content"])?;
            p.add_unescaped_ascii_extent(128)?;
            project_reference(&mut p)?;
        }
        _ => return Err(refused()),
    }
    if response {
        p.add_object()?;
    }
    p.add_object()?;
    p.finish(usize::MAX)
}

pub(super) fn observe_response(
    body: &ResponseBody,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    match &body.shape {
        ResponseShape::Accepted {
            operation_state,
            result,
            extensions,
        }
        | ResponseShape::Completed {
            operation_state,
            result,
            extensions,
        } => {
            observer.observe(operation_state)?;
            observer.observe(result)?;
            observer.observe(extensions)?;
        }
        ResponseShape::Error {
            operation_state,
            error,
            extensions,
        } => {
            observer.observe(operation_state)?;
            observer.observe(error)?;
            observer.observe(extensions)?;
        }
    }
    match &body.result {
        None => Ok(()),
        Some(MethodResult::BlobBegin(value)) => {
            observer.observe(&value.transfer_id)?;
            observer.observe(&value.next_offset)?;
            observer.observe(&value.maximum_chunk_bytes)
        }
        Some(MethodResult::BlobChunk(value)) => {
            observer.observe(&value.transfer_id)?;
            observer.observe(&value.next_offset)
        }
        Some(MethodResult::BlobFinish(value)) => {
            observer.observe(&value.transfer_id)?;
            observer.observe(&value.content)
        }
        _ => Err(refused()),
    }
}

fn object(p: &mut Projection, fields: &[&str]) -> Result<(), ProviderError> {
    p.add_object()?;
    for key in fields {
        p.add_field(key)?;
    }
    Ok(())
}
fn growth(n: usize) -> Result<usize, ProviderError> {
    add(mul(2, n)?, 4)
}
fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(credit)
}
fn mul(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_mul(b).ok_or_else(credit)
}
fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0, |n, x| add(n, *x))
}
