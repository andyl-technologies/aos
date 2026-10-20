//! Prices the seven actual typed role references and ordinary Blob phases.
//!
//! This reuses the existing fixed baseline envelope projector. It borrows real
//! fullrefs, counts actual frame multiplicities and original custody capacity,
//! and never passes through the old six-input Prepare/mapping owner.

use super::*;
use crate::retained_metadata::{
    requested_metadata_backing_storage_data as backing, requested_storage::tree_storage_data,
};
use std::mem::align_of;

pub(super) struct Parts {
    pub(super) chunk: usize,
    pub(super) maximum_chunk: usize,
    pub(super) requests: usize,
    pub(super) retained: usize,
    pub(super) transient: usize,
}

pub(super) fn counter_scratch_data() -> usize {
    CnpController::original_native_import18_assignment_counter_scratch_data()
        + CnpController::original_complete_restore_input_upload_counter_scratch_data()
        + retained_counter_scratch_data()
        + OriginalNativeImport18Assignment::receive_counter_scratch_data()
        + ReceivedFrame::native_import17_upload_counter_scratch_data()
        + size_of::<Parts>()
        + size_of::<Result<Parts, ProviderError>>()
        + size_of::<InputUploadBank>()
        + size_of::<InputUpload>()
        + size_of::<OriginalNativeImport18InputUploadStorageData>()
        + size_of::<super::prospective::OriginalNativeImport18InputUploadProspectiveStorageData>()
        + size_of::<
            Result<
                super::prospective::OriginalNativeImport18InputUploadProspectiveStorageData,
                ProviderError,
            >,
        >()
        + size_of::<[&String; 4]>()
        + size_of::<std::array::IntoIter<&'static String, 4>>()
        + size_of::<[u8; 8]>()
        + size_of::<Result<OriginalNativeImport18InputUploadStorageData, ProviderError>>()
        + size_of::<UploadFrame>()
        + size_of::<publication::UploadExecution<'static>>()
        + size_of::<&OriginalFreshRestoreQuery>()
        + size_of::<&OriginalCanonicalBlobAckEmitter>()
        + size_of::<&PacketCompleteRestorePrepareRequest>()
        + size_of::<&PacketNativeImport18Binding>()
        + size_of::<&Id>()
        + size_of::<&OriginalNativeImport18Assignment>()
        + size_of::<&mut OriginalNativeImport18Assignment>()
        + size_of::<&CnpController>()
        + size_of::<&mut CnpController>()
        + size_of::<Inputs<'static>>()
        + size_of::<Result<Inputs<'static>, ProviderError>>()
        + size_of::<[&[u8]; 7]>()
        + size_of::<[&ContentRef; 7]>()
        + size_of::<[usize; 7]>()
        + size_of::<[Option<ContentRef>; 7]>()
        + size_of::<[Option<Id>; 7]>()
        + size_of::<std::array::IntoIter<PacketNativeImport18InputRole, 7>>()
        + size_of::<std::slice::Iter<'static, &'static ContentRef>>()
        + size_of::<std::slice::Iter<'static, UploadFrame>>()
        + size_of::<std::slice::IterMut<'static, UploadFrame>>()
        + size_of::<std::collections::TryReserveError>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Option<U64>>()
        + size_of::<Option<OriginalProtocolStorageFacts>>()
        + ClientCustody::native_import18_upload_custody_counter_scratch_data()
        + size_of::<std::str::Bytes<'static>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<Result<(), ProviderError>>()
}

pub(super) fn quote(
    controller: &CnpController,
    inputs: &Inputs<'_>,
    allocation: &PacketCompleteRestoreInputAllocation,
    maximum: usize,
) -> Result<Parts, ProviderError> {
    quote_references(
        controller,
        &inputs.references,
        inputs.prefix()?,
        allocation,
        0,
        maximum,
    )
}

pub(super) fn quote_references(
    controller: &CnpController,
    references: &[&ContentRef; 7],
    prefix: blake3::Hash,
    allocation: &PacketCompleteRestoreInputAllocation,
    preceding_pairs: usize,
    maximum: usize,
) -> Result<Parts, ProviderError> {
    let frame_maximum = controller.maximum_frame()?;
    let negotiated_chunk = usize::try_from(controller.authority().limits().blob_chunk_bytes.get())
        .map_err(|_| credit())?;
    let maximum_chunk = negotiated_chunk.min(4096);
    let chunk = maximum_chunk.min(frame_maximum.saturating_sub(4096).saturating_mul(3) / 4);
    if chunk == 0 {
        return Err(credit());
    }
    let mut requests = 0usize;
    for reference in references {
        requests = add(
            requests,
            add(
                usize::try_from(reference.length.get())
                    .map_err(|_| credit())?
                    .div_ceil(chunk),
                2,
            )?,
        )?;
    }
    let chunks = requests.checked_sub(14).ok_or_else(credit)?;
    if u64::try_from(chunks).map_err(|_| credit())? > allocation.maximum_nodes.get() {
        return Err(credit());
    }
    let prefix = prefix.to_hex();
    // All selected IDs share this cryptographic actual-Prepare prefix. Existing
    // cached IDs with that prefix conservatively refuse before any ID allocation.
    if controller
        .custody
        .native_import18_upload_prefix_conflicts_data(prefix.as_str())
    {
        return Err(refused());
    }
    let cache = controller
        .custody
        .fresh_query_cache_requested_layout_data(add(requests, preceding_pairs)?)?;
    let mut retained = sum(&[
        size_of::<InputUpload>(),
        size_of::<OriginalNativeImport18InputUploadStorageData>(),
        size_of::<super::prospective::OriginalNativeImport18InputUploadProspectiveStorageData>(),
        mul(requests, size_of::<UploadFrame>())?,
        mul(requests, growth(128)?)?,
        mul(7, growth(128)?)?,
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
    // Each strict raw Value and byte bank remains in its actual frame. Extra
    // RawValue/typed constructor growth is separately admitted per received row.
    retained = add(
        retained,
        sum(&[
            mul(requests, add(raw_receive, frame_maximum)?)?,
            size_of::<RequestBody>(),
            size_of::<NotificationBody>(),
        ])?,
    )?;
    let mut work = 0usize;
    let mut literal = 0usize;
    for reference in references {
        retained = add(retained, backing(&metadata::facts(*reference)?)?)?;
        for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
            let count = if method == Method::BlobChunk {
                usize::try_from(reference.length.get())
                    .map_err(|_| credit())?
                    .div_ceil(chunk)
            } else {
                1
            };
            let request = super::super::super::restore_upload::storage::held_prefix_frame(
                controller, *reference, method, false, chunk,
            )?;
            let response = super::super::super::restore_upload::storage::held_prefix_frame(
                controller, *reference, method, true, chunk,
            )?;
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
    // Selected-schema checks occur in four concrete per-frame calls: sequence
    // for the original, exchange entry, immediately before send, and after ACK.
    // The remaining whole-upload checks are named independently below. None of
    // them renews the original operational cut or history allowance.
    let (contract, _) = native_import18_contract_storage_data(usize::MAX)?;
    let per_frame_selection = sum(&[contract, contract, contract, contract])?;
    let quote_selection = sum(&[contract, contract, contract, contract])?;
    let entry_selection = sum(&[contract, contract, contract])?;
    let finish_selection = sum(&[contract, contract, contract, contract])?;
    let transient = sum(&[
        work,
        mul(requests, per_frame_selection)?,
        // Each resumed publication checks the same seven borrowed bodies.
        mul(requests, mul(7, 85)?)?,
        quote_selection,
        entry_selection,
        finish_selection,
        size_of::<InputUpload>(),             // InputUpload::new return
        size_of::<InputUpload>(),             // Vec::push owning argument
        size_of::<[Option<ContentRef>; 7]>(), // first from_fn result in InputUpload::new
        size_of::<[Option<Id>; 7]>(),         // second from_fn result in InputUpload::new
        size_of::<UploadFrame>(),             // append_plan owning frame argument
        size_of::<BlobBeginRequest>(),
        size_of::<BlobChunkRequest>(),
        size_of::<BlobFinishRequest>(),
        size_of::<Envelope>(),
        raw_receive,
        size_of::<crate::transport::RetainedFrame>(),
        size_of::<Option<crate::transport::RetainedFrame>>(),
        size_of::<ReceivedFrame>(),
        size_of::<ResponseBody>(),
        size_of::<RequestBody>(),
    ])?;
    if sum(&[retained, transient, counter_scratch_data()])? > maximum {
        return Err(credit());
    }
    Ok(Parts {
        chunk,
        maximum_chunk,
        requests,
        retained,
        transient,
    })
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
fn refused() -> ProviderError {
    invalid()
}
