//! Counts closed successful Blob frames without allocating hypothetical bodies.

use super::*;
use crate::reference_packet::service::native_startup::contract_value::ContractValue as V;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as Data, OriginalSerializationStorageProjection as Projection,
};

const REQUEST: V<'static> = V::Object(&[
    (
        "schema",
        V::Text(PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE),
    ),
    ("scope", super::super::projection::SCOPE),
    ("role", V::Text("coordinator")),
    ("coordinator", super::super::projection::CONTENT),
    ("manifest", super::super::projection::CONTENT),
    ("maximum_frame_bytes", V::Text("18446744073709551615")),
    ("chunk_bytes", V::Text("18446744073709551615")),
    ("maximum_requests", V::Text("18446744073709551615")),
    ("native_allocation", super::super::projection::ROW),
]);
const ARTIFACT: V<'static> = V::Object(&[
    ("request", REQUEST),
    (
        "proof",
        V::Object(&[
            (
                "schema",
                V::Text("source-owned.packet-restoration-activation-upload-proof/1"),
            ),
            ("algorithm", V::Text("blake3-256-mac")),
            (
                "context_digest",
                V::Text("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
            (
                "mac",
                V::Text("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
        ]),
    ),
]);

pub(super) fn frame(
    method: Method,
    response: bool,
    chunk: usize,
    maximum: usize,
) -> Result<Data, ProviderError> {
    let mut p = Projection::new(maximum)?;
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
    p.add_string(if response { "response" } else { "request" })?;
    // Exact finite identifier widths dominate nullable fields as well. This
    // does not construct a route or supply actual origin/claim identities.
    for _ in 0..7 {
        p.add_unescaped_ascii_extent(128)?;
    }
    p.add_unescaped_ascii_extent(20)?;
    p.add_value(&method)?;
    if response {
        object(
            &mut p,
            &["status", "operation_state", "result", "extensions"],
        )?;
        p.add_string("completed")?;
        p.add_string("completed")?;
    }
    match (method, response) {
        (Method::BlobBegin, false) => {
            object(&mut p, &["transfer_id", "content", "extensions"])?;
            p.add_unescaped_ascii_extent(128)?;
            p.add_value(&super::super::projection::CONTENT)?;
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
            p.add_unescaped_ascii_extent(chunk.div_ceil(3).checked_mul(4).ok_or_else(invalid)?)?;
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
            p.add_value(&super::super::projection::CONTENT)?;
        }
        _ => return Err(invalid()),
    }
    if response {
        p.add_object()?;
    }
    p.add_object()?;
    if !response && method == Method::BlobBegin {
        p.add_field(PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE)?;
        p.add_value(&ARTIFACT)?;
    }
    p.finish(maximum)
}

fn object(p: &mut Projection, keys: &[&str]) -> Result<(), ProviderError> {
    p.add_object()?;
    for key in keys {
        p.add_field(key)?;
    }
    Ok(())
}
