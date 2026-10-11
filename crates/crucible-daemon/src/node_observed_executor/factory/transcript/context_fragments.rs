//! Lossless bounded fragments of an original installed source context object.
//!
//! The fragment manifest is a new selected context encoding. It retains the
//! original raw bytes and ContentRef without rewriting any semantic source field.
//! Reconstruction is pure data validation, never source qualification.

use super::*;
use serde::{Deserialize, Serialize};

pub(super) const FRAGMENT_MEDIA_TYPE: &str =
    "application/vnd.crucible.installed-recording-context-fragments.v1+json";
const FORMAT: &str = "crucible.installed-recording-context-fragments";
const CHUNK_BYTES: usize = 32 * 1024;
const MAXIMUM_CHUNKS: usize = 2_048;
const MAXIMUM_SOURCE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fragment {
    offset: U64,
    content: ContentRef,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    original: ContentRef,
    chunk_bytes: U64,
    chunks: Vec<Fragment>,
}

pub(super) fn fragment_source_object(
    original: InputPayload,
) -> Result<Vec<InputPayload>, NodeObservedError> {
    if original.bytes.len() > MAXIMUM_SOURCE_BYTES {
        return Err(refused(
            "original recording context exceeds source byte credit",
        ));
    }
    original.reference.verify(&original.bytes)?;
    if original.bytes.len() <= CHUNK_BYTES {
        return Ok(vec![original]);
    }
    let count = original.bytes.len().div_ceil(CHUNK_BYTES);
    if count > MAXIMUM_CHUNKS {
        return Err(refused(
            "original recording context exceeds fragment credit",
        ));
    }
    let mut objects = Vec::new();
    objects.try_reserve_exact(count + 1).map_err(native)?;
    let mut chunks = Vec::new();
    chunks.try_reserve_exact(count).map_err(native)?;
    for (index, bytes) in original.bytes.chunks(CHUNK_BYTES).enumerate() {
        let reference = canonical::content_ref(bytes, "application/octet-stream")?;
        let offset = index
            .checked_mul(CHUNK_BYTES)
            .ok_or_else(|| refused("source fragment offset overflow"))?;
        chunks.push(Fragment {
            offset: U64::new(offset as u64),
            content: reference.clone(),
        });
        objects.push(InputPayload {
            reference,
            bytes: bytes.to_vec(),
        });
    }
    let manifest = Manifest {
        format: FORMAT.into(),
        schema_version: 1,
        original: original.reference,
        chunk_bytes: U64::new(CHUNK_BYTES as u64),
        chunks,
    };
    let bytes = canonical::canonical_json(&serde_json::to_value(manifest)?)?;
    objects.push(InputPayload {
        reference: canonical::content_ref(&bytes, FRAGMENT_MEDIA_TYPE)?,
        bytes,
    });
    Ok(objects)
}

pub(super) fn reconstruct_source_object(
    manifest: &InputPayload,
    objects: &[InputPayload],
    maximum_bytes: usize,
) -> Result<InputPayload, NodeObservedError> {
    manifest.reference.verify(&manifest.bytes)?;
    if manifest.reference.media_type != FRAGMENT_MEDIA_TYPE {
        return Err(refused("unsupported source context fragment media type"));
    }
    let value = canonical::parse_json(&manifest.bytes, 1024 * 1024)?;
    let data: Manifest = serde_json::from_value(value)?;
    data.original.validate()?;
    let length = usize::try_from(data.original.length.get())
        .map_err(|_| refused("source context extent is not representable"))?;
    if data.format != FORMAT
        || data.schema_version != 1
        || data.chunk_bytes.get() != CHUNK_BYTES as u64
        || length <= CHUNK_BYTES
        || length > maximum_bytes.min(MAXIMUM_SOURCE_BYTES)
        || data.chunks.len() != length.div_ceil(CHUNK_BYTES)
        || data.chunks.len() > MAXIMUM_CHUNKS
    {
        return Err(refused("invalid bounded source context fragment geometry"));
    }
    // Validate the complete original extent and every chunk before allocating
    // the reconstructed body. No absent data is fetched or inferred from hashes.
    let mut offset = 0usize;
    for chunk in &data.chunks {
        if chunk.content.media_type != "application/octet-stream" {
            return Err(refused("unsupported source context chunk media type"));
        }
        let body = objects
            .iter()
            .find(|object| object.reference == chunk.content)
            .ok_or_else(|| refused("original recording context fragment absent"))?;
        let expected = (length - offset).min(CHUNK_BYTES);
        if chunk.offset.get() != offset as u64 || body.bytes.len() != expected {
            return Err(refused(
                "original recording context fragment order or extent differs",
            ));
        }
        body.reference.verify(&body.bytes)?;
        offset = offset
            .checked_add(body.bytes.len())
            .ok_or_else(|| refused("source fragment extent overflow"))?;
    }
    if offset != length {
        return Err(refused("original recording context extent is incomplete"));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(native)?;
    for chunk in &data.chunks {
        let body = objects
            .iter()
            .find(|object| object.reference == chunk.content)
            .ok_or_else(|| refused("validated source context fragment disappeared"))?;
        bytes.extend_from_slice(&body.bytes);
    }
    data.original.verify(&bytes)?;
    Ok(InputPayload {
        reference: data.original,
        bytes,
    })
}

#[cfg(test)]
#[path = "context_fragment_tests.rs"]
mod tests;
