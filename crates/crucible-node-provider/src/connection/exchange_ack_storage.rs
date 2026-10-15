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
    let trees = super::super::super::restore_input_quote::tree_storage(
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
    let tree = super::super::super::restore_input_quote::tree_storage(
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
    let sort_tree = super::super::super::restore_input_quote::tree_storage(
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
