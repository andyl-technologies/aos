//! Bounded File.slice reads, checksum pre-pass and exact original-part rechecks.

use wasm_bindgen_futures::JsFuture;
use web_sys::{Blob, File};

use crate::direct_upload_model::{SourceAccumulator, SourcePart, SOURCE_CHUNK_BYTES};

/// Validates the exact browser source length against the protocol hard limit.
///
/// # Errors
/// Returns an error for nonintegral, nonfinite or oversized source lengths.
pub(super) fn file_size(file: &File) -> Result<u64, String> {
    let size = file.size();
    if !size.is_finite()
        || size < 0.0
        || size.fract() != 0.0
        || size > aos_proto_types::direct_upload::MAX_DIRECT_OBJECT_BYTES as f64
    {
        return Err("The selected file exceeds the direct upload limit".into());
    }
    Ok(size as u64)
}

/// Measures the full original source and part checksums using bounded slices.
///
/// # Errors
/// Returns an error for read failures or a changed source length.
pub(super) async fn inspect(file: &File) -> Result<(String, Vec<SourcePart>), String> {
    hash_range(file, 0, file_size(file)?).await
}

async fn hash_range(
    file: &File,
    start: u64,
    size: u64,
) -> Result<(String, Vec<SourcePart>), String> {
    let mut source = SourceAccumulator::new(size)?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| "The selected source range is invalid".to_string())?;
    let mut position = start;
    while position < end {
        let next = position.saturating_add(SOURCE_CHUNK_BYTES as u64).min(end);
        let slice = file
            .slice_with_f64_and_f64(position as f64, next as f64)
            .map_err(|_| "The browser could not read the selected file".to_string())?;
        let buffer = JsFuture::from(slice.array_buffer())
            .await
            .map_err(|_| "The browser could not read the selected file".to_string())?;
        let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
        if bytes.len() as u64 != next - position {
            return Err("The selected file changed during upload".into());
        }
        source.push(&bytes)?;
        position = next;
    }
    source.finish()
}

/// Rechecks the original source range before returning its streamed Blob.
///
/// # Errors
/// Returns an error for changed source bytes/range or a failed slice read.
pub(super) async fn verified_part(file: &File, original: &SourcePart) -> Result<Blob, String> {
    let (sha, parts) = hash_range(file, original.offset, original.size).await?;
    if sha != original.sha256 || parts.len() != 1 || parts[0].md5 != original.md5 {
        return Err("The selected file changed; reselect the original upload source".into());
    }
    let end = original
        .offset
        .checked_add(original.size)
        .ok_or_else(|| "The original upload range is invalid".to_string())?;
    let body = file
        .slice_with_f64_and_f64(original.offset as f64, end as f64)
        .map_err(|_| "The browser could not read the original upload part".to_string())?;
    if body.size() != original.size as f64 {
        return Err("The selected file changed during upload".into());
    }
    Ok(body)
}
