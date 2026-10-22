//! Quotes the closed response decoder independently of opaque Source producers.
//!
//! The raw frame, original SDK maps, Source callbacks and subsequent receipt MAC
//! verification are separate components. Borrowed derived struct decoding uses
//! no internally tagged ResponseShape buffer; its completed variant is built
//! directly from the allocation-free closed body check.

use super::*;
use crate::reference_packet::continuation_models::serde_partials::{
    self, DecoderPartial, decoder_struct,
};
use crate::retained_metadata::requested_storage::tree_storage_data;
use crucible_node_format::values::MAX_ID_BYTES;
use std::mem::align_of;

decoder_struct!(PacketNativeImport18BootstrapResult {
    schema,
    state,
    recipe_identity,
    initial_funding
});
decoder_struct!(PacketNativeImport18BootstrapAckReceipt {
    schema,
    algorithm,
    state,
    context_digest,
    assigned_response,
    mac
});

impl DecoderPartial for PacketNativeImport18BootstrapAckState {
    const DIAGNOSTIC_NAMES_BYTES: usize =
        "PacketNativeImport18BootstrapAckState".len() + "bootstrap_only".len() + "``".len();

    fn partial_counter_data() -> usize {
        size_of::<Self>() + size_of::<Result<Self, serde_json::Error>>()
    }
}

const _: fn(PacketNativeImport18BootstrapAckState) = |state| match state {
    PacketNativeImport18BootstrapAckState::BootstrapOnly => (),
};

// base64 0.22.1 decodes a 43-byte unpadded digest into a capacity-33 bank,
// then truncates its length to 32 without shrinking its allocation.
const DIGEST_CAPACITY: usize = ((43usize / 4) + 1) * 3;

/// Names component demand without admitting raw input or issuing Source credit.
#[derive(Clone, Copy)]
pub struct PacketNativeImport18BootstrapResponseDecodeRowData {
    pub(super) axes: [usize; 3],
}

impl PacketNativeImport18BootstrapResponseDecodeRowData {
    /// Returns retained, simultaneous transient and fixed-control requested bytes.
    pub const fn requested_storage_data(self) -> [usize; 3] {
        self.axes
    }
}

/// Quotes every closed response output and actual decoder/diagnostic partial.
///
/// The quote must be independently admitted beside the complete Source holder
/// before decoding. `maximum` restricts demand; it is never an allowance. The
/// defining preflight must run unchanged before any of the quoted decoders.
///
/// # Errors
/// Refuses checked layout overflow, unsupported tree layout or a short restriction.
pub fn native_import18_bootstrap_response_decode_quote_data(
    maximum: usize,
) -> Result<PacketNativeImport18BootstrapResponseDecodeRowData, ProviderError> {
    let envelope = sum(&[trees(6, 18)?, envelope_text()?])?;
    let body = sum(&[trees(3, 7)?, result_text()?])?;
    let request = sum(&[
        NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.len(),
        DIGEST_CAPACITY,
    ])?;
    let result = sum(&[
        NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA.len(),
        DIGEST_CAPACITY,
    ])?;
    let receipt = sum(&[
        NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.len(),
        PACKET_COMPLETE_RESTORE_ALGORITHM.len(),
        3 * DIGEST_CAPACITY,
    ])?;
    let retained = sum(&[
        size_of::<PacketNativeImport18BootstrapResponseDecodeData>(),
        envelope,
        body,
        request,
        result,
        receipt,
    ])?;

    let names = sum(&[
        Envelope::DIAGNOSTIC_NAMES_BYTES,
        PacketNativeImport18BootstrapRequest::DIAGNOSTIC_NAMES_BYTES,
        PacketNativeImport18BootstrapResult::DIAGNOSTIC_NAMES_BYTES,
        PacketNativeImport18BootstrapAckReceipt::DIAGNOSTIC_NAMES_BYTES,
    ])?;
    let diagnostic_text = sum(&[
        envelope_text()?.checked_mul(6).ok_or_else(exhausted)?,
        names,
        serde_partials::diagnostic_format_text_bytes_data(),
        size_of::<[u8; 20]>(),
    ])?;
    let diagnostic = diagnostic_text
        .checked_mul(8)
        .and_then(|n| n.checked_add(8))
        .ok_or_else(exhausted)?;
    let transient = sum(&[
        envelope,
        body,
        request,
        result,
        receipt,
        diagnostic,
        serde_partials::diagnostic_error_impl_allocation_upper_bytes_data(),
        Envelope::partial_counter_data(),
        PacketNativeImport18BootstrapRequest::partial_counter_data(),
        PacketNativeImport18BootstrapResult::partial_counter_data(),
        PacketNativeImport18BootstrapAckReceipt::partial_counter_data(),
        43,
        DIGEST_CAPACITY,
        4 * 20,
        MAX_ID_BYTES,
        size_of::<Envelope>(),
        size_of::<Option<Envelope>>(),
        size_of::<Result<Envelope, serde_json::Error>>(),
        size_of::<PacketNativeImport18BootstrapRequest>(),
        size_of::<Option<PacketNativeImport18BootstrapRequest>>(),
        size_of::<Result<PacketNativeImport18BootstrapRequest, serde_json::Error>>(),
        size_of::<ResponseShape>(),
        size_of::<Option<ResponseShape>>(),
        size_of::<Map<String, Value>>(),
        size_of::<PacketNativeImport18BootstrapResult>(),
        size_of::<Option<PacketNativeImport18BootstrapResult>>(),
        size_of::<Result<PacketNativeImport18BootstrapResult, serde_json::Error>>(),
        size_of::<PacketNativeImport18BootstrapAckReceipt>(),
        size_of::<Option<PacketNativeImport18BootstrapAckReceipt>>(),
        size_of::<Result<PacketNativeImport18BootstrapAckReceipt, serde_json::Error>>(),
        size_of::<PacketNativeImport18BootstrapResponseDecodeData>(),
        size_of::<Option<PacketNativeImport18BootstrapResponseDecodeData>>(),
        size_of::<PacketNativeImport18BootstrapResponseDecodeFailureData>() * 2,
        size_of::<Option<PacketNativeImport18BootstrapResponseDecodeFailureData>>(),
    ])?;
    let axes = [
        retained,
        transient,
        native_import18_bootstrap_response_decode_counter_scratch_data(),
    ];
    if sum(&axes)? > maximum {
        return Err(exhausted());
    }
    Ok(PacketNativeImport18BootstrapResponseDecodeRowData { axes })
}

fn trees(count: usize, entries: usize) -> Result<usize, ProviderError> {
    tree_storage_data(
        count,
        entries,
        size_of::<String>() + size_of::<Value>(),
        align_of::<String>().max(align_of::<Value>()),
    )
}

fn result_text() -> Result<usize, ProviderError> {
    let mut total = sum(&[
        NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA.len(),
        "bootstrap_only".len(),
        43,
        3 * 20,
    ])?;
    for key in preflight::RESULT_FIELDS
        .into_iter()
        .chain(preflight::FUNDING_FIELDS)
    {
        total = sum(&[total, key.len()])?;
    }
    Ok(total)
}

fn envelope_text() -> Result<usize, ProviderError> {
    let mut total = sum(&[
        "CNP/1".len(),
        7 * MAX_ID_BYTES,
        "completed".len() * 2,
        result_text()?,
        NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.len(),
        PACKET_COMPLETE_RESTORE_ALGORITHM.len(),
        "bootstrap_only".len(),
        3 * 43,
    ])?;
    for key in preflight::BODY_FIELDS
        .into_iter()
        .chain([NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT])
        .chain(preflight::RECEIPT_FIELDS)
    {
        total = sum(&[total, key.len()])?;
    }
    Ok(total)
}

pub(super) fn retained_data(
    attempt: &PacketNativeImport18BootstrapResponseDecodeData,
) -> Result<usize, ProviderError> {
    let PacketNativeImport18BootstrapResponseDecodeData {
        row: _,
        step: _,
        envelope,
        request,
        body,
        result,
        receipt,
        failure: _,
        decoded: _,
        failed: _,
    } = attempt;
    let mut observer = MetadataObserver::new();
    if let Some(envelope) = envelope {
        let Envelope {
            protocol,
            message: _,
            session_id,
            incarnation_id,
            node_id,
            execution_owner_id,
            capture_owner_id,
            request_id,
            operation_id,
            sequence: _,
            method: _,
            body,
            extensions,
        } = envelope;
        observer.observe(protocol)?;
        observer.observe(session_id)?;
        observer.observe(incarnation_id)?;
        observer.observe(node_id)?;
        observer.observe(execution_owner_id)?;
        observer.observe(capture_owner_id)?;
        observer.observe(request_id)?;
        observer.observe(operation_id)?;
        observer.observe(body)?;
        observer.observe(extensions)?;
    }
    if let Some(request) = request {
        PacketNativeImport18BootstrapRetainedData::Request(request).observe_data(&mut observer)?;
    }
    if let Some(body) = body {
        match body {
            ResponseShape::Completed {
                operation_state: _,
                result,
                extensions,
            } => {
                observer.observe(result)?;
                observer.observe(extensions)?;
            }
            ResponseShape::Accepted { .. } | ResponseShape::Error { .. } => return Err(refused()),
        }
    }
    if let Some(result) = result {
        PacketNativeImport18BootstrapRetainedData::Result(result).observe_data(&mut observer)?;
    }
    if let Some(receipt) = receipt {
        PacketNativeImport18BootstrapRetainedData::Receipt(receipt).observe_data(&mut observer)?;
    }
    sum(&[
        size_of::<PacketNativeImport18BootstrapResponseDecodeData>(),
        requested_metadata_backing_storage_data(&observer.finish())?,
    ])
}

/// Names actual borrowed decode, preflight, inspection, census and quote controls.
///
/// These are explicit DATA/control layouts, not compiler stack-frame bounds.
pub fn native_import18_bootstrap_response_decode_counter_scratch_data() -> usize {
    preflight::counter_scratch_data()
        + Envelope::partial_counter_data() + PacketNativeImport18BootstrapRequest::partial_counter_data()
        + PacketNativeImport18BootstrapResult::partial_counter_data() + PacketNativeImport18BootstrapAckReceipt::partial_counter_data()
        + native_import18_bootstrap_retention_counter_scratch_data()
        + size_of::<PacketNativeImport18BootstrapResponseDecodeHistoryData<'static>>()
        + size_of::<PacketNativeImport18BootstrapResponseDecodeRowData>()
        + size_of::<Result<PacketNativeImport18BootstrapResponseDecodeRowData, ProviderError>>()
        + size_of::<&mut Option<PacketNativeImport18BootstrapResponseDecodeData>>()
        + size_of::<Option<&mut PacketNativeImport18BootstrapResponseDecodeData>>()
        + size_of::<Result<&mut PacketNativeImport18BootstrapResponseDecodeData, ProviderError>>()
        + size_of::<&mut PacketNativeImport18BootstrapResponseDecodeData>()
        + size_of::<&PacketNativeImport18BootstrapResponseDecodeData>()
        + size_of::<Option<PacketNativeImport18BootstrapResponseDecodeStep>>()
        + size_of::<PacketNativeImport18BootstrapResponseDecodeFailureData>()
        + size_of::<RequestMapDecoder<'static>>()
        + size_of::<std::iter::Map<serde_json::map::Iter<'static>, BorrowedFieldMapper>>()
        + size_of::<MetadataObserver<'static>>() + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<[usize; 6]>() + size_of::<[usize; 35]>() + size_of::<[usize; 5]>()
        + size_of::<std::iter::Chain<std::array::IntoIter<&str, 4>, std::array::IntoIter<&str, 3>>>()
        + size_of::<std::iter::Chain<std::iter::Chain<std::array::IntoIter<&str, 4>, std::array::IntoIter<&str, 1>>, std::array::IntoIter<&str, 6>>>()
        + size_of::<std::slice::Iter<'static, usize>>() + size_of::<&[usize]>()
        + size_of::<[Option<usize>; 2]>() + size_of::<[usize; 10]>()
        + size_of::<[Result<(), ProviderError>; 6]>() + size_of::<Result<usize, ProviderError>>()
        // Five nested closed census frames coexist with the defining field walk.
        + 5 * (size_of::<&Value>() + size_of::<&String>() + size_of::<(&String, &Value)>()
            + size_of::<serde_json::map::Iter<'static>>() + size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
            + size_of::<&mut MetadataObserver<'static>>() + size_of::<Result<(), ProviderError>>())
}

pub(super) fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(exhausted)
    })
}
