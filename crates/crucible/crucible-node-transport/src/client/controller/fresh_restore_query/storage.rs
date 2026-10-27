//! Counts actual host query private layouts and closed prospective field owners.
//!
//! The full negotiated raw parser/error phase remains separate from successful
//! closed proof DTO/cache copies. Native publication rows are not reused as host
//! allowance. Constants bound field grammars; byte counts are never multiplied
//! into a guessed heap factor.

use super::*;
use crate::reference_packet::control::PacketControlSelection;
use crate::retained_metadata::requested_metadata_backing_storage_data as backing;
use crate::retained_metadata::requested_storage::tree_storage_data;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as Data, OriginalSerializationStorageProjection as Projection,
    actual_serialization_storage_data,
};
use std::mem::{align_of, size_of};

pub(super) struct Parts {
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) query_typed: usize,
}

pub(super) const fn counter_scratch_data() -> usize {
    size_of::<OriginalFreshRestoreQueryStorageData>()
        + size_of::<Parts>() + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + 8 * size_of::<Data>() + 2 * size_of::<Projection>()
        + crate::reference_packet::service::fresh_restore_allocation::fresh_restore_allocation_startup_counter_scratch_data()
        + size_of::<blake3::Hasher>() + 20
        + 32 + size_of::<base64::DecodeSliceError>()
        + size_of::<&crucible_node_format::OwnerBinding>()
}

pub(super) fn quote(
    controller: &CnpController,
    selection: &PacketControlSelection,
    admit: &Envelope,
    admit_response: &Envelope,
) -> Result<Parts, ProviderError> {
    let maximum = usize::MAX;
    let shapes = crate::reference_packet::service::fresh_restore_allocation::fresh_restore_allocation_host_shapes(selection, maximum)?;
    let frame_limit = controller.maximum_frame()?;
    let chunk = usize::try_from(controller.authority().limits().blob_chunk_bytes.get())
        .map_err(|_| refused())?
        .min(4096);
    if chunk == 0
        || shapes.original.maximum_encoded_bytes > frame_limit
        || shapes.terminal.maximum_encoded_bytes > frame_limit
    {
        return Err(refused());
    }
    let requests = add(
        2,
        MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES.div_ceil(chunk),
    )?;
    let [owner] = selection.realization.owner_bindings.as_slice() else {
        return Err(refused());
    };
    let identity = actual(owner)?;
    let digest_work = add(
        actual(admit)?.requested_total()?,
        actual(admit_response)?.requested_total()?,
    )?;
    let current = controller.original_owned11_metadata_facts()?;
    let containment = add(backing(&current)?, size_of::<CnpController>())?;
    let content = controller
        .custody
        .content()
        .fresh_report_requested_layout_data(growth(
            MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES,
        )?)?;
    let cache = controller
        .custody
        .fresh_query_cache_requested_layout_data(requests)?;
    let reference = reference_data()?;
    let identity_hash_backing = sum(&[
        growth(64)?,
        growth("cnp.request.provider.v1".len())?,
        growth("blake3-256".len())?,
    ])?;
    let mut retained = sum(&[
        size_of::<OriginalFreshRestoreQuery>(),
        size_of::<OriginalFreshRestoreQueryStorageData>(),
        shapes.query_typed_requested_bytes,
        shapes.report_typed_requested_bytes,
        shapes.receipt_typed_requested_bytes,
        content,
        cache,
        // Original custody + Source owner each retain full request/terminal.
        mul(2, shapes.original.dom_and_canonical_scratch_bytes)?,
        mul(2, shapes.terminal.dom_and_canonical_scratch_bytes)?,
        size_of::<ResponseBody>(),
        // Shape raw result and separately decoded ObserveResult each own
        // independent inventory-hash strings in the Source completion owner.
        mul(2, shapes.terminal.dom_and_canonical_scratch_bytes)?,
        mul(add(requests, 1)?, add(growth(128)?, identity_hash_backing)?)?,
        // Transfer key, object key and independently cloned full references.
        mul(2, growth(128)?)?,
        mul(3, reference.dom_and_canonical_scratch_bytes)?,
    ])?;
    let mut proof_work = 0usize;
    let mut literal_bytes = add(
        shapes.original.maximum_encoded_bytes,
        shapes.terminal.maximum_encoded_bytes,
    )?;
    for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
        let repetitions = if method == Method::BlobChunk {
            MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES.div_ceil(chunk)
        } else {
            1
        };
        let request = frame(controller.authority(), method, false, chunk)?;
        let response = frame(controller.authority(), method, true, chunk)?;
        if request.maximum_encoded_bytes > frame_limit
            || response.maximum_encoded_bytes > frame_limit
        {
            return Err(refused());
        }
        literal_bytes = add(
            literal_bytes,
            mul(
                repetitions,
                add(
                    request.maximum_encoded_bytes,
                    response.maximum_encoded_bytes,
                )?,
            )?,
        )?;
        retained = add(
            retained,
            mul(
                repetitions,
                sum(&[
                    request.dom_and_canonical_scratch_bytes,
                    response.dom_and_canonical_scratch_bytes,
                    size_of::<ClientOriginal>(),
                    growth(128)?,
                    identity_hash_backing,
                ])?,
            )?,
        )?;
        // Each original identity/envelope_bytes pass and decoded body/guard
        // copy is a separately named current receive/ACK phase. Sum all frames
        // conservatively instead of assuming sequential temporary reuse.
        proof_work = add(
            proof_work,
            mul(
                repetitions,
                sum(&[
                    mul(4, request.requested_total()?)?,
                    mul(4, response.requested_total()?)?,
                    size_of::<RequestBody>(),
                    size_of::<ResponseBody>(),
                    growth(chunk)?,
                    growth(chunk.div_ceil(3).checked_mul(4).ok_or_else(refused)?)?,
                ])?,
            )?,
        )?;
    }
    retained = add(
        retained,
        tree_storage_data(
            3,
            3,
            size_of::<Id>() + size_of::<Envelope>(),
            align_of::<Id>().max(align_of::<Envelope>()),
        )?,
    )?;
    let transient = sum(&[
        // Full raw R and incident/error owners remain required even though the
        // successful typed grammar is restricted before body construction.
        controller.session.fresh_query_raw_receive_storage_data()?,
        controller.session.fresh_report_decode_storage_data()?,
        // Before closed report validation, all decoded Bytes can together own
        // at most the report input extent; explicit RawVec growth covers that
        // typed buffer in addition to the generic raw/DOM/error primitive.
        growth(MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES)?,
        size_of::<PacketNativeFreshRestoreAllocationReport>(),
        containment,
        proof_work,
        identity.requested_total()?,
        digest_work,
        mul(4, shapes.original.requested_total()?)?,
        mul(4, shapes.terminal.requested_total()?)?,
        shapes.report_authentication_transient_requested_bytes,
        shapes.query.requested_total()?,
        shapes.report.requested_total()?,
        size_of::<Envelope>(),
        size_of::<ResponseBody>(),
        size_of::<crate::connection::ReceivedFrame>(),
    ])?;
    let frontier = controller.original_native5_storage_facts()?;
    let slots = add(add(requests, 1)?, add(requests, 1)?)?;
    if add(frontier.incoming_frames, add(requests, 1)?)? > frontier.maximum_frames_per_direction
        || add(frontier.outgoing_frames, add(requests, 1)?)? > frontier.maximum_frames_per_direction
        || add(
            frontier.retained_bytes,
            sum(&[literal_bytes, mul(slots, 4)?, frame_limit])?,
        )? > frontier.maximum_history_bytes
    {
        return Err(refused());
    }
    controller.preflight_source_reply(
        1,
        requests,
        add(literal_bytes, frame_limit)?,
        1,
        MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES,
    )?;
    Ok(Parts {
        retained,
        transient,
        query_typed: shapes.query_typed_requested_bytes,
    })
}

pub(super) fn authenticate_query_capacity(
    query: &PacketNativeFreshRestoreAllocationQuery,
    maximum: usize,
) -> Result<(), ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(query)?;
    if add(
        size_of::<PacketNativeFreshRestoreAllocationQuery>(),
        backing(&observer.finish())?,
    )? > maximum
    {
        return Err(refused());
    }
    Ok(())
}

fn actual(
    value: &(impl Serialize + crate::retained_metadata::ObserveMetadata),
) -> Result<Data, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(value)?;
    actual_serialization_storage_data(value, observer.finish(), usize::MAX)
}

fn frame(
    authority: &crate::handshake::ConnectionAuthority,
    method: Method,
    response: bool,
    chunk: usize,
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
    p.add_value(authority.session_id())?;
    p.add_value(authority.incarnation_id())?;
    for _ in 0..4 {
        p.add_value(&())?;
    }
    p.add_string_extent(128)?;
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
    match method {
        Method::BlobBegin => {
            if response {
                object(
                    &mut p,
                    &["transfer_id", "next_offset", "maximum_chunk_bytes"],
                )?;
                p.add_string_extent(128)?;
                p.add_unescaped_ascii_extent(20)?;
                p.add_unescaped_ascii_extent(20)?;
            } else {
                object(&mut p, &["transfer_id", "content", "extensions"])?;
                p.add_string_extent(128)?;
                reference(&mut p)?;
                p.add_object()?;
            }
        }
        Method::BlobChunk => {
            if response {
                object(&mut p, &["transfer_id", "next_offset"])?;
                p.add_string_extent(128)?;
                p.add_unescaped_ascii_extent(20)?;
            } else {
                object(&mut p, &["transfer_id", "offset", "bytes", "extensions"])?;
                p.add_string_extent(128)?;
                p.add_unescaped_ascii_extent(20)?;
                p.add_unescaped_ascii_extent(
                    chunk.div_ceil(3).checked_mul(4).ok_or_else(refused)?,
                )?;
                p.add_object()?;
            }
        }
        Method::BlobFinish => {
            if response {
                object(&mut p, &["transfer_id", "content"])?;
                p.add_string_extent(128)?;
                reference(&mut p)?;
            } else {
                object(&mut p, &["transfer_id", "extensions"])?;
                p.add_string_extent(128)?;
                p.add_object()?;
            }
        }
        _ => return Err(refused()),
    }
    if response {
        p.add_object()?;
    }
    p.add_object()?;
    p.finish(usize::MAX)
}

fn reference_data() -> Result<Data, ProviderError> {
    let mut p = Projection::new(usize::MAX)?;
    reference(&mut p)?;
    p.finish(usize::MAX)
}
fn reference(p: &mut Projection) -> Result<(), ProviderError> {
    object(p, &["hash", "length", "media_type"])?;
    object(p, &["algorithm", "domain", "digest"])?;
    p.add_string("blake3-256")?;
    p.add_string("cnp.blob.v1")?;
    p.add_unescaped_ascii_extent(64)?;
    p.add_unescaped_ascii_extent(20)?;
    p.add_string(PACKET_FRESH_RESTORE_ALLOCATION_MEDIA)
}
fn object(p: &mut Projection, fields: &[&str]) -> Result<(), ProviderError> {
    p.add_object()?;
    for field in fields {
        p.add_field(field)?;
    }
    Ok(())
}
fn growth(bytes: usize) -> Result<usize, ProviderError> {
    add(mul(2, bytes)?, 4)
}
fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(refused)
}
fn mul(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_mul(b).ok_or_else(refused)
}
fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0, |a, b| add(a, *b))
}

pub(super) fn observe_response(
    response: &ResponseBody,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let ResponseBody { shape, result } = response;
    match shape {
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
    match result {
        None => Ok(()),
        Some(MethodResult::Observe(result)) => {
            let ObserveResult {
                observations,
                next_sequence,
                complete,
                inventory_hash,
            } = result;
            observer.observe(observations)?;
            observer.observe(next_sequence)?;
            observer.observe(complete)?;
            observer.observe(inventory_hash)
        }
        Some(_) => Err(refused()),
    }
}

#[cfg(test)]
mod tests {
    //! Compares the prospective grammar to an actual baseline ACK struct.
    // crucible-lint: panic-shortcut: fixture assertions stop on a sizing mismatch.
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn host_begin_ack_projection_includes_real_maximum_chunk_field() -> TestResult {
        let (_, authority, _, _) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let result = serde_json::to_value(BlobBeginResult {
            transfer_id: Id::new("packet-transfer-4")?,
            next_offset: U64::new(0),
            maximum_chunk_bytes: U64::new(4096),
        })?;
        let Value::Object(result) = result else {
            return Err(refused().into());
        };
        let body = serde_json::to_value(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result,
            extensions: Extensions::new(),
        })?;
        let Value::Object(body) = body else {
            return Err(refused().into());
        };
        let envelope = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Response,
            session_id: Nullable(Some(authority.session_id().clone())),
            incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: Nullable(Some(Id::new("packet-proof-4")?)),
            sequence: U64::new(8),
            method: Method::BlobBegin,
            body,
            extensions: Extensions::new(),
        };
        let actual = actual(&envelope)?;
        let predicted = frame(&authority, Method::BlobBegin, true, 4096)?;
        assert!(actual.maximum_encoded_bytes <= predicted.maximum_encoded_bytes);
        assert!(
            actual.dom_and_canonical_scratch_bytes <= predicted.dom_and_canonical_scratch_bytes
        );
        assert!(
            actual.projected_parser_requested_bytes <= predicted.projected_parser_requested_bytes
        );
        assert!(actual.requested_total()? <= predicted.requested_total()?);
        Ok(())
    }
}
