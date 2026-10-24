//! Preserves the full original ACK geometry independently of shared suppliers.
//!
//! Only the tree helper path changes for this deeper test-only module.

//! Bounds closed continuing Blob ACK caches and one terminating open frame.
//!
//! The actual native packet validator stops at the first Error, noncompleted or
//! mismatched ACK. Every ACK that can precede it has empty extensions and only
//! the closed Blob result fields. An arbitrary negotiated raw frame is still
//! parsed; its DOM, Error details and canonical numeric spelling are charged
//! once as a terminating peak. This is not a smaller raw-frame allowance.

use super::*;
use crate::bodies::{BlobBeginResult, BlobChunkResult, BlobFinishResult};

pub(super) fn successful_ack_storage() -> Result<usize, ProviderError> {
    // One full JSON-envelope/response/result/content/hash grammar has at most
    // 26 entries in six objects. Three independent copies bound retained raw
    // body, ResponseShape.result and the decoded Blob result's owned strings.
    let trees = crate::connection::restore_input_quote::tree_storage(
        3 * 6,
        3 * (13 + 4 + 3 + 3 + 3),
        size_of::<String>() + size_of::<Value>(),
        align_of::<String>().max(align_of::<Value>()),
    )?;
    let keys = [
        "protocol",
        "message",
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "request_id",
        "operation_id",
        "sequence",
        "method",
        "body",
        "extensions",
        "status",
        "operation_state",
        "result",
        "transfer_id",
        "next_offset",
        "maximum_chunk_bytes",
        "content",
        "hash",
        "algorithm",
        "digest",
        "domain",
        "length",
        "media_type",
    ];
    let key_bytes = keys
        .iter()
        .try_fold(0usize, |sum, key| add(sum, key.len()))?;
    let strings = sum(&[
        mul(3, key_bytes)?,
        // All scope/transfer IDs satisfy the actual Id128 contract; proof
        // headers are in fact narrower, but their actual equality is separate.
        mul(3 * 8, 128)?,
        mul(3, "blake3-256".len() + "cnp.blob.v1".len() + 64 + 128)?,
        3 * (5 + 9 + 9 + 20 + 20 + 20),
    ])?;
    sum(&[
        trees,
        strings,
        size_of::<ResponseBody>(),
        size_of::<BlobBeginResult>()
            .max(size_of::<BlobChunkResult>())
            .max(size_of::<BlobFinishResult>()),
    ])
}

pub(super) fn open_ack_storage(bytes: usize) -> Result<usize, ProviderError> {
    if bytes == 0 || bytes > crate::transport::MAX_FRAME_BYTES {
        return Err(credit());
    }
    let entries = bytes / 4;
    let elements = bytes / 2;
    // Nested singleton arrays have only two exclusive delimiter bytes each.
    // Count those separately from elements; min4/growth is charged per array.
    let arrays = bytes / 2;
    let arrays_requested = mul(add(mul(2, elements)?, mul(4, arrays)?)?, size_of::<Value>())?;
    let tree = crate::connection::restore_input_quote::tree_storage(
        entries,
        entries,
        size_of::<String>() + size_of::<Value>(),
        align_of::<String>().max(align_of::<Value>()),
    )?;
    let dom = sum(&[bytes, arrays_requested, tree, size_of::<Value>()])?;
    let parser = add(dom, growth(bytes)?)?;

    // canonical.rs uses only finite ryu-js::Buffer::format. The source-pinned
    // Buffer has132 bytes (including its larger toFixed storage). This bounds
    // any numeric token independently of its short input spelling; strings can
    // escape to six bytes per UTF-8 input byte. No number-free assumption is
    // made for Error details or untrusted negotiated extension JSON.
    const PINNED_RYU_BUFFER_BYTES: usize = 132;
    let canonical = mul(PINNED_RYU_BUFFER_BYTES + 6 + 1, bytes)?;
    let sort_keys = mul(add(mul(4, bytes)?, mul(8, entries)?)?, size_of::<u16>())?;
    let sort_tree = crate::connection::restore_input_quote::tree_storage(
        entries,
        entries,
        size_of::<Vec<u16>>() + size_of::<(&str, &Value)>(),
        align_of::<Vec<u16>>().max(align_of::<(&str, &Value)>()),
    )?;
    // ErrorRecord validation may canonicalize details while the outer body
    // canonical bank remains alive. Other raw/shape/result clones fit within
    // four complete DOM budgets, including the failed result retained in the
    // actual record before the private validator refuses it.
    let validation = sum(&[
        mul(4, dom)?,
        mul(2, growth(canonical)?)?,
        sort_keys,
        sort_tree,
        growth(add(mul(6, bytes)?, 2)?)?,
        size_of::<ResponseBody>(),
        size_of::<ReceivedFrame>(),
        serde_error_storage(bytes)?,
    ])?;
    sum(&[bytes, parser, validation])
}

pub(super) fn serde_error_storage(bytes: usize) -> Result<usize, ProviderError> {
    // Pinned serde_json1.0.150 ErrorImpl has ErrorCode +line/column usize.
    // ErrorCode's only payloads are Box<str> and io::Error; a full usize tag
    // plus per-field alignment padding conservatively bounds that private
    // enum/box request from its actual source, without an invented mirror T.
    let alignment = align_of::<Box<str>>()
        .max(align_of::<std::io::Error>())
        .max(align_of::<usize>());
    let boxed_error = sum(&[
        size_of::<Box<str>>().max(size_of::<std::io::Error>()),
        3 * size_of::<usize>(),
        mul(4, alignment - 1)?,
    ])?;
    // Generated closed Envelope/Blob/response errors quote one offending
    // string (Debug escaping <=6*UTF8 bytes), expected-field/variant roster,
    // fixed grammar text and two decimal source coordinates. The formatter's
    // String and final Box<str> may coexist during shrink-to-fit.
    let fixed_names = [
        "protocol",
        "message",
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "request_id",
        "operation_id",
        "sequence",
        "method",
        "body",
        "extensions",
        "status",
        "operation_state",
        "result",
        "error",
        "code",
        "retryable",
        "details",
        "effect",
        "transfer_id",
        "next_offset",
        "maximum_chunk_bytes",
        "content",
        "hash",
        "algorithm",
        "digest",
        "domain",
        "length",
        "media_type",
        "accepted",
        "completed",
        "error",
        "ResponseShape",
        "BlobBeginResult",
        "BlobChunkResult",
        "BlobFinishResult",
        "Envelope",
    ];
    let names = fixed_names
        .iter()
        .try_fold(0usize, |sum, name| add(sum, name.len()))?;
    let text = sum(&[mul(6, bytes)?, mul(4, names)?, 256, 2 * 20])?;
    sum(&[boxed_error, growth(text)?, text])
}

/// Separates one terminating raw ACK's owners from its returning validation.
///
/// Error details and every uncertain raw/decoded owner remain persistent. This
/// DATA neither restricts input nor substitutes the closed successful-ACK bound.
pub(super) struct OpenAckLifetimeStorageData {
    pub(super) retained: usize,
    pub(super) returning: usize,
}

pub(super) fn open_ack_lifetime_storage_data(
    bytes: usize,
) -> Result<OpenAckLifetimeStorageData, ProviderError> {
    if bytes == 0 || bytes > crate::transport::MAX_FRAME_BYTES {
        return Err(credit());
    }
    let entries = bytes / 4;
    let elements = bytes / 2;
    // Nested singleton arrays have only two exclusive delimiter bytes each.
    // Count those separately from elements; min4/growth is charged per array.
    let arrays = bytes / 2;
    let arrays_requested = mul(add(mul(2, elements)?, mul(4, arrays)?)?, size_of::<Value>())?;
    let tree = crate::connection::restore_input_quote::tree_storage(
        entries,
        entries,
        size_of::<String>() + size_of::<Value>(),
        align_of::<String>().max(align_of::<Value>()),
    )?;
    let dom = sum(&[bytes, arrays_requested, tree, size_of::<Value>()])?;
    let parser = add(dom, growth(bytes)?)?;

    // canonical.rs uses only finite ryu-js::Buffer::format. The source-pinned
    // Buffer has132 bytes (including its larger toFixed storage). This bounds
    // any numeric token independently of its short input spelling; strings can
    // escape to six bytes per UTF-8 input byte. No number-free assumption is
    // made for Error details or untrusted negotiated extension JSON.
    const PINNED_RYU_BUFFER_BYTES: usize = 132;
    let canonical = mul(PINNED_RYU_BUFFER_BYTES + 6 + 1, bytes)?;
    let sort_keys = mul(add(mul(4, bytes)?, mul(8, entries)?)?, size_of::<u16>())?;
    let sort_tree = crate::connection::restore_input_quote::tree_storage(
        entries,
        entries,
        size_of::<Vec<u16>>() + size_of::<(&str, &Value)>(),
        align_of::<Vec<u16>>().max(align_of::<(&str, &Value)>()),
    )?;
    // ErrorRecord validation may canonicalize details while the outer body
    // canonical bank remains alive. Other raw/shape/result clones fit within
    // four complete DOM budgets, including the failed result retained in the
    // actual record before the private validator refuses it.
    // All five complete DOM budgets stay persistent: this conservatively
    // includes raw Envelope/body, decoded Error details and uncertain partials.
    // Keep raw/growth, error formatting/box, response and incident-facing
    // headers too. Only canonical output/sort work is returned by validation.
    let retained = sum(&[
        bytes,
        parser,
        mul(4, dom)?,
        growth(add(mul(6, bytes)?, 2)?)?,
        size_of::<ResponseBody>(),
        size_of::<ReceivedFrame>(),
        serde_error_storage(bytes)?,
    ])?;
    let returning = sum(&[mul(2, growth(canonical)?)?, sort_keys, sort_tree])?;
    if add(retained, returning)? != open_ack_storage(bytes)? {
        return Err(credit());
    }
    Ok(OpenAckLifetimeStorageData {
        retained,
        returning,
    })
}

pub(super) const fn open_ack_lifetime_counter_scratch_data() -> usize {
    size_of::<OpenAckLifetimeStorageData>()
        + size_of::<Result<OpenAckLifetimeStorageData, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<[usize; 7]>()
        + size_of::<[usize; 4]>()
        + size_of::<[usize; 3]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        // entries/elements/arrays, array/tree/DOM/parser and canonical/sort
        // extents are the same explicit scalar formula views as the old quote.
        + 12 * size_of::<usize>()
}

/// Bounds only emitted canonical bytes for the selected original native read.
///
/// Pinned ryu-js::raw::format64 writes at most 25 bytes. The larger 132-byte
/// Buffer also serves toFixed and remains independently named in scratch.
/// Counting each raw byte once for each of numeric output, six-byte string
/// escaping and punctuation is deliberately conservative. No number-free or
/// locally expected input shape is assumed, including terminating Error details.
fn native_original_canonical_output_bytes(bytes: usize) -> Result<usize, ProviderError> {
    if bytes == 0 || bytes > crate::transport::MAX_FRAME_BYTES {
        return Err(credit());
    }
    mul(25 + 6 + 1, bytes)
}

/// Retains the old open-frame owners and narrows only returning output banks.
///
/// Only the selected original native Observe publisher and its restricted first
/// query use this projection. Their canonicalized bodies are unchanged raw
/// subtrees, or independently bounded original Blob request bodies. The generic
/// full quote and its exact partition stay unchanged for other callers.
pub(super) fn native_original_open_ack_lifetime_storage_data(
    bytes: usize,
) -> Result<OpenAckLifetimeStorageData, ProviderError> {
    let old = open_ack_lifetime_storage_data(bytes)?;
    let old_output = mul(2, growth(mul(132 + 6 + 1, bytes)?)?)?;
    let new_output = mul(2, growth(native_original_canonical_output_bytes(bytes)?)?)?;
    let returning = old
        .returning
        .checked_sub(old_output)
        .and_then(|work| work.checked_add(new_output))
        .ok_or_else(credit)?;
    if returning > old.returning {
        return Err(credit());
    }
    Ok(OpenAckLifetimeStorageData {
        retained: old.retained,
        returning,
    })
}

pub(super) fn native_original_open_ack_storage(bytes: usize) -> Result<usize, ProviderError> {
    let data = native_original_open_ack_lifetime_storage_data(bytes)?;
    add(data.retained, data.returning)
}

/// Names the complete selected return views and the unchanged formatter buffer.
pub(super) const fn native_original_open_ack_counter_scratch_data() -> usize {
    open_ack_lifetime_counter_scratch_data()
        + 2 * size_of::<OpenAckLifetimeStorageData>()
        + 2 * size_of::<Result<OpenAckLifetimeStorageData, ProviderError>>()
        + 4 * size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + 6 * size_of::<usize>()
        // Exact pinned Buffer layout is one [MaybeUninit<u8>; 132].
        + size_of::<[u8; 132]>()
}

/// Names only local counter/facts/hash scratch, excluding recursive frames.
pub(super) const fn original_packet_prefix_quote_scratch_bytes_data() -> usize {
    size_of::<OriginalPacketPrefixStorageData>()
        + size_of::<Projection>()
        + 4 * size_of::<OriginalSerializationStorageData>()
        + 2 * size_of::<MetadataObserver<'static>>()
        + 2 * size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<blake3::Hasher>()
        + size_of::<Body<'static>>()
        + 20
        + "blake3-256".len()
        + "cnp.blob.v1".len()
        + 64
}
