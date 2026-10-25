//! Bounds closed continuing Blob ACK caches and one terminating open frame.
//!
//! The actual native packet validator stops at the first Error, noncompleted or
//! mismatched ACK. Every ACK that can precede it has empty extensions and only
//! the closed Blob result fields. An arbitrary negotiated raw frame is still
//! parsed; its DOM, Error details and canonical numeric spelling are charged
//! once as a terminating peak. This is not a smaller raw-frame allowance.

use crate::ProviderError;
use crate::profile::requested_storage::tree_storage_data as tree_storage;
use serde_json::Value;
use std::mem::{align_of, size_of};

/// Limits JSON bytes in one CNP/1 frame before body allocation.
pub const MAX_FRAME_BYTES: usize = 16_777_216;

/// Carries the actual upper response and Blob result header widths.
///
/// These inert byte counts are not private layout definitions, native owners,
/// allocation grants, frame allowances or provenance/currentness evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckFixedLayoutData {
    /// Reports the actual compiled response-body header.
    pub response_body_bytes: usize,
    /// Reports the actual retained received-frame header.
    pub received_frame_bytes: usize,
    /// Reports the largest of the actual Begin, Chunk and Finish result headers.
    pub maximum_blob_result_bytes: usize,
}

/// Bounds the closed successful Blob acknowledgement owners.
///
/// # Errors
/// Preserves checked tree-layout and requested-storage overflow refusals.
pub fn successful_ack_storage(fixed: &AckFixedLayoutData) -> Result<usize, ProviderError> {
    // One full JSON-envelope/response/result/content/hash grammar has at most
    // 26 entries in six objects. Three independent copies bound retained raw
    // body, ResponseShape.result and the decoded Blob result's owned strings.
    let trees = tree_storage(
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
        fixed.response_body_bytes,
        fixed.maximum_blob_result_bytes,
    ])
}

/// Bounds one terminating raw acknowledgement without reducing its frame allowance.
///
/// # Errors
/// Refuses zero or oversized input extents, unsupported layouts or arithmetic overflow.
pub fn open_ack_storage(bytes: usize, fixed: &AckFixedLayoutData) -> Result<usize, ProviderError> {
    if bytes == 0 || bytes > MAX_FRAME_BYTES {
        return Err(credit());
    }
    let entries = bytes / 4;
    let elements = bytes / 2;
    // Nested singleton arrays have only two exclusive delimiter bytes each.
    // Count those separately from elements; min4/growth is charged per array.
    let arrays = bytes / 2;
    let arrays_requested = mul(add(mul(2, elements)?, mul(4, arrays)?)?, size_of::<Value>())?;
    let tree = tree_storage(
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
    let sort_tree = tree_storage(
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
        fixed.response_body_bytes,
        fixed.received_frame_bytes,
        serde_error_storage(bytes)?,
    ])?;
    sum(&[bytes, parser, validation])
}

const SERDE_ERROR_FIELD_NAMES: usize = 39;

/// Names the fixed error-quote roster, arithmetic arrays and returning controls.
///
/// Diagnostic backing remains separate. The roster length also types the
/// actual array below, so adding a field requires review of this declaration.
pub const fn serde_error_storage_counter_scratch_data() -> usize {
    size_of::<[&str; SERDE_ERROR_FIELD_NAMES]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<[usize; 4]>()
        + size_of::<[usize; 3]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + 3 * size_of::<Result<usize, ProviderError>>()
        + 2 * size_of::<Option<usize>>()
        + 10 * size_of::<usize>()
}

/// Bounds the original retained serde error and its formatting banks.
///
/// # Errors
/// Preserves checked requested-storage overflow refusals.
pub fn serde_error_storage(bytes: usize) -> Result<usize, ProviderError> {
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
    let fixed_names: [&str; SERDE_ERROR_FIELD_NAMES] = [
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
pub struct OpenAckLifetimeStorageData {
    /// Counts persistent raw, parsed and uncertain owners.
    pub retained: usize,
    /// Counts temporary canonicalization and sorting work returned by validation.
    pub returning: usize,
}

/// Separates retained raw owners from returning validation work.
///
/// # Errors
/// Preserves raw-length, layout, overflow and partition-consistency refusals.
pub fn open_ack_lifetime_storage_data(
    bytes: usize,
    fixed: &AckFixedLayoutData,
) -> Result<OpenAckLifetimeStorageData, ProviderError> {
    if bytes == 0 || bytes > MAX_FRAME_BYTES {
        return Err(credit());
    }
    let entries = bytes / 4;
    let elements = bytes / 2;
    // Nested singleton arrays have only two exclusive delimiter bytes each.
    // Count those separately from elements; min4/growth is charged per array.
    let arrays = bytes / 2;
    let arrays_requested = mul(add(mul(2, elements)?, mul(4, arrays)?)?, size_of::<Value>())?;
    let tree = tree_storage(
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
    let sort_tree = tree_storage(
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
        fixed.response_body_bytes,
        fixed.received_frame_bytes,
        serde_error_storage(bytes)?,
    ])?;
    let returning = sum(&[mul(2, growth(canonical)?)?, sort_keys, sort_tree])?;
    if add(retained, returning)? != open_ack_storage(bytes, fixed)? {
        return Err(credit());
    }
    Ok(OpenAckLifetimeStorageData {
        retained,
        returning,
    })
}

/// Names fixed lifetime counter views and the two actual lower facts inputs.
pub const fn open_ack_lifetime_counter_scratch_data() -> usize {
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
        // The lifetime input and its nested open-ACK input are new borrowed facts.
        + 2 * size_of::<&AckFixedLayoutData>()
}

/// Bounds only emitted canonical bytes for the selected original native read.
///
/// Pinned ryu-js::raw::format64 writes at most 25 bytes. The larger 132-byte
/// Buffer also serves toFixed and remains independently named in scratch.
/// Counting each raw byte once for each of numeric output, six-byte string
/// escaping and punctuation is deliberately conservative. No number-free or
/// locally expected input shape is assumed, including terminating Error details.
///
/// # Errors
/// Refuses zero or oversized input extents and checked arithmetic overflow.
pub fn native_original_canonical_output_bytes(bytes: usize) -> Result<usize, ProviderError> {
    if bytes == 0 || bytes > MAX_FRAME_BYTES {
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
///
/// # Errors
/// Preserves the original raw-length, arithmetic and nonincreasing-output checks.
pub fn native_original_open_ack_lifetime_storage_data(
    bytes: usize,
    fixed: &AckFixedLayoutData,
) -> Result<OpenAckLifetimeStorageData, ProviderError> {
    let old = open_ack_lifetime_storage_data(bytes, fixed)?;
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

/// Sums the original native retained and returning acknowledgement extents.
///
/// # Errors
/// Preserves native lifetime, raw-length and checked-sum refusals.
pub fn native_original_open_ack_storage(
    bytes: usize,
    fixed: &AckFixedLayoutData,
) -> Result<usize, ProviderError> {
    let data = native_original_open_ack_lifetime_storage_data(bytes, fixed)?;
    add(data.retained, data.returning)
}

/// Names the complete selected return views and the unchanged formatter buffer.
pub const fn native_original_open_ack_counter_scratch_data() -> usize {
    open_ack_lifetime_counter_scratch_data()
        + 2 * size_of::<OpenAckLifetimeStorageData>()
        + 2 * size_of::<Result<OpenAckLifetimeStorageData, ProviderError>>()
        + 4 * size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + 6 * size_of::<usize>()
        // Exact pinned Buffer layout is one [MaybeUninit<u8>; 132].
        + size_of::<[u8; 132]>()
        // Scalar/native-lifetime inputs add two loans beside lifetime/open above.
        + 2 * size_of::<&AckFixedLayoutData>()
}

fn growth(bytes: usize) -> Result<usize, ProviderError> {
    add(mul(bytes, 4)?, 256)
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(credit)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(credit)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |sum, value| add(sum, *value))
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("original packet prefix requested storage")
}
